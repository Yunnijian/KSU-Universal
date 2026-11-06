// SPDX-License-Identifier: GPL-2.0
/*
 * BakaSU module_load_filter, adapted to the universal syscall dispatcher.
 *
 * Matching modules are acknowledged with success but not loaded. If the
 * blocklist is empty the hook is a pass-through.
 */
#include <asm/elf.h>
#include <asm/unistd.h>
#include <linux/elf.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#include <uapi/linux/module.h>
#endif

#include "arch.h"
#include "feature/module_load_filter.h"
#include "klog.h" // IWYU pragma: keep

char ksu_baka_block_modules[256];
module_param_string(block_modules, ksu_baka_block_modules, sizeof(ksu_baka_block_modules), 0);
MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");

struct ksu_baka_module_name {
    const char *name;
    size_t len;
};

struct ksu_baka_elf_reader {
    const char __user *umod;
    unsigned long umod_len;
    struct file *file;
    loff_t file_size;
};

static int ksu_baka_reader_read(struct ksu_baka_elf_reader *r, loff_t offset, void *buf, size_t len)
{
    loff_t total = r->umod ? (loff_t)r->umod_len : r->file_size;

    if (len == 0)
        return -EINVAL;
    if (offset < 0 || (loff_t)len > total || offset > total - (loff_t)len)
        return -ERANGE;

    if (r->umod) {
        if (copy_from_user(buf, r->umod + offset, len))
            return -EFAULT;
        return 0;
    }

    {
        loff_t pos = offset;
        ssize_t n = kernel_read(r->file, buf, len, &pos);
        if (n < 0 || (size_t)n != len)
            return -EIO;
    }
    return 0;
}

static bool ksu_baka_should_block(const char *name, size_t name_len, bool normalize_filename,
                                  struct ksu_baka_module_name *blocked)
{
    const char *cursor = ksu_baka_block_modules;
    const char *end = cursor + strnlen(cursor, sizeof(ksu_baka_block_modules));

    while (cursor < end) {
        const char *separator = memchr(cursor, ',', end - cursor);
        size_t entry_len = separator ? (size_t)(separator - cursor) : (size_t)(end - cursor);

        if (entry_len && name_len == entry_len) {
            size_t i;

            for (i = 0; i < name_len; i++) {
                char a = name[i];
                char b = cursor[i];

                if (normalize_filename && a == '-')
                    a = '_';
                if (b == '-')
                    b = '_';
                if (a != b)
                    break;
            }

            if (i == name_len) {
                blocked->name = cursor;
                blocked->len = entry_len;
                return true;
            }
        }

        if (!separator)
            break;
        cursor = separator + 1;
    }

    return false;
}

static bool ksu_baka_is_block_module(struct ksu_baka_elf_reader *r, struct ksu_baka_module_name *blocked)
{
    Elf_Ehdr ehdr;
    Elf_Shdr *shdrs = NULL;
    char *shstrtab = NULL;
    char *modinfo = NULL;
    Elf_Shdr *shstr_sh;
    Elf_Shdr *modinfo_sh = NULL;
    unsigned int shnum, i;
    unsigned long shtab_bytes;
    bool should_block = false;

    if (ksu_baka_reader_read(r, 0, &ehdr, sizeof(ehdr)))
        return false;

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
        return false;
    if (ehdr.e_ident[EI_CLASS] != ELF_CLASS || ehdr.e_ident[EI_DATA] != ELF_DATA ||
        ehdr.e_ident[EI_VERSION] != EV_CURRENT)
        return false;
    if (ehdr.e_type != ET_REL || !elf_check_arch(&ehdr) || ehdr.e_version != EV_CURRENT)
        return false;
    if (ehdr.e_shentsize != sizeof(Elf_Shdr))
        return false;

    shnum = ehdr.e_shnum;
    if (shnum == 0 || shnum > 512)
        return false;
    if (ehdr.e_shstrndx >= shnum)
        return false;

    shtab_bytes = (unsigned long)shnum * sizeof(Elf_Shdr);
    shdrs = kmalloc(shtab_bytes, GFP_KERNEL);
    if (!shdrs)
        return false;
    if (ksu_baka_reader_read(r, ehdr.e_shoff, shdrs, shtab_bytes))
        goto out;

    shstr_sh = &shdrs[ehdr.e_shstrndx];
    if (shstr_sh->sh_type != SHT_STRTAB || shstr_sh->sh_size == 0 || shstr_sh->sh_size > 65536)
        goto out;
    shstrtab = kmalloc(shstr_sh->sh_size, GFP_KERNEL);
    if (!shstrtab)
        goto out;
    if (ksu_baka_reader_read(r, shstr_sh->sh_offset, shstrtab, shstr_sh->sh_size))
        goto out;

    for (i = 0; i < shnum; i++) {
        Elf_Shdr *sh = &shdrs[i];
        const char *name;
        unsigned long remaining;

        if (sh->sh_name >= shstr_sh->sh_size)
            continue;
        name = shstrtab + sh->sh_name;
        remaining = shstr_sh->sh_size - sh->sh_name;
        if (strnlen(name, remaining) >= remaining)
            continue;
        if (sh->sh_type == SHT_PROGBITS && strcmp(name, ".modinfo") == 0) {
            modinfo_sh = sh;
            break;
        }
    }
    if (!modinfo_sh)
        goto out;

    if (modinfo_sh->sh_size == 0 || modinfo_sh->sh_size > 16384)
        goto out;
    modinfo = kmalloc(modinfo_sh->sh_size, GFP_KERNEL);
    if (!modinfo)
        goto out;
    if (ksu_baka_reader_read(r, modinfo_sh->sh_offset, modinfo, modinfo_sh->sh_size))
        goto out;

    {
        const char *p = modinfo;
        const char *end = modinfo + modinfo_sh->sh_size;

        while (p < end) {
            const char *nul = memchr(p, '\0', end - p);
            size_t entlen;

            if (!nul)
                break;
            entlen = nul - p;
            if (entlen > 5 && memcmp(p, "name=", 5) == 0) {
                const char *val = p + 5;
                size_t vlen = entlen - 5;

                should_block = ksu_baka_should_block(val, vlen, false, blocked);
                break;
            }
            p = nul + 1;
        }
    }

out:
    kfree(modinfo);
    kfree(shstrtab);
    kfree(shdrs);
    return should_block;
}

/* 1 = let the original syscall run, 0 = acknowledge without loading. */
static int ksu_baka_handle_init_module(const void __user *umod, unsigned long umod_len)
{
    struct ksu_baka_module_name blocked = { 0 };
    struct ksu_baka_elf_reader r = {
        .umod = (const char __user *)umod,
        .umod_len = umod_len,
    };

    if (r.umod && r.umod_len >= sizeof(Elf_Ehdr) && ksu_baka_is_block_module(&r, &blocked)) {
        pr_info("module_load_filter: block %.*s load due to it in blocklist\n",
                (int)blocked.len, blocked.name);
        return 0;
    }

    return 1;
}

static int ksu_baka_handle_finit_module(int fd, int flags)
{
    struct ksu_baka_module_name blocked = { 0 };
    struct file *file;
    bool should_block = false;

    file = fget(fd);
    if (!file)
        return 0;

#ifdef MODULE_INIT_COMPRESSED_FILE
    if (flags & MODULE_INIT_COMPRESSED_FILE) {
        static const char *const compression_suffixes[] = { ".gz", ".xz", ".zst" };
        const struct qstr *filename = &file->f_path.dentry->d_name;
        size_t name_len = filename->len;
        size_t i;

        for (i = 0; i < ARRAY_SIZE(compression_suffixes); i++) {
            const char *suffix = compression_suffixes[i];
            size_t suffix_len = strlen(suffix);

            if (name_len > suffix_len &&
                !memcmp(filename->name + name_len - suffix_len, suffix, suffix_len)) {
                name_len -= suffix_len;
                break;
            }
        }

        if (i != ARRAY_SIZE(compression_suffixes) &&
            name_len > 3 && !memcmp(filename->name + name_len - 3, ".ko", 3)) {
            name_len -= 3;
            should_block = ksu_baka_should_block(filename->name, name_len, true, &blocked);
        }
    } else
#endif
    {
        struct ksu_baka_elf_reader r = {
            .file = file,
            .file_size = i_size_read(file_inode(file)),
        };

        should_block = r.file_size >= (loff_t)sizeof(Elf_Ehdr) &&
                       ksu_baka_is_block_module(&r, &blocked);
    }

    fput(file);

    if (should_block) {
        pr_info("module_load_filter: block %.*s load due to it in blocklist\n",
                (int)blocked.len, blocked.name);
        return 0;
    }

    return 1;
}

long ksu_baka_module_load(int orig_nr, const struct pt_regs *regs, bool *handled)
{
    *handled = false;

    if (!ksu_baka_block_modules[0])
        return 0;

    if (orig_nr == __NR_init_module) {
        if (!ksu_baka_handle_init_module((const void __user *)PT_REGS_PARM1(regs),
                                         (unsigned long)PT_REGS_PARM2(regs))) {
            *handled = true;
            return 0;
        }
        return 0;
    }

    if (orig_nr == __NR_finit_module) {
        if (!ksu_baka_handle_finit_module((int)PT_REGS_PARM1(regs), (int)PT_REGS_PARM3(regs))) {
            *handled = true;
            return 0;
        }
        return 0;
    }

    return 0;
}
