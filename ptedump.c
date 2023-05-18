#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/migrate.h>
#include <linux/cdev.h>

MODULE_DESCRIPTION("Provide a char device to read a PTE and dump a page from va");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alistair Popple");

#define PTDUMP_DUMP_PAGE (0x1)

struct cdev cdev;
static int dev_major = 0;
static struct class *ptedump_class = NULL;

static int get_pte(struct mm_struct *mm, unsigned long address,
		   pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		goto out;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out;

	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	*ptepp = ptep;
	return 0;

out:
	return -EFAULT;
}

static unsigned long get_pte_page(unsigned long pid, unsigned long addr,
				  unsigned long *pte_out, struct page **page_out)
{
	struct task_struct *task;
	struct pid *pid_struct;
	struct page *page = NULL;
	spinlock_t *ptl;
	pte_t *ptep;
	pte_t pte;

	if (pid) {
		pid_struct = find_get_pid(pid);
		if (pid_struct) {
			task = get_pid_task(pid_struct, PIDTYPE_PID);
			put_pid(pid_struct);
		}

		if (!task || !pid_struct)
			return -ESRCH;
	} else {
		task = current;
	}

	if (get_pte(task->mm, addr, &ptep, &ptl))
		return -EFAULT;

	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;

		entry = pte_to_swp_entry(pte);
		if (is_pfn_swap_entry(entry)) {
			page = pfn_swap_entry_to_page(entry);
		}
	} else {
		page = pte_page(pte);
	}

	if (page)
		get_page(page);

	pte_unmap_unlock(ptep, ptl);

	if (page_out)
		*page_out = page;
	else if (page)
		put_page(page);

	if (pid)
		put_task_struct(task);

	*pte_out = pte_val(pte);
	return 0;
}

static int ptedump_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int ptedump_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int ptedump_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t ptedump_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    char data[21];
    int len;

    len = snprintf(data, 20, "0x%016lx\n", (unsigned long) file->private_data);
    if (copy_to_user(buf, data, len))
	return -EFAULT;

    return len;
}

#define MAX_PTDUMP_DATA_LEN 39

static ssize_t ptedump_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
	char data[MAX_PTDUMP_DATA_LEN];
	char *tok, *sep = data;
	unsigned long pid = 0, va, flags = 0, pte;
	struct page *page;
	int ret;

	if (count > MAX_PTDUMP_DATA_LEN)
		return -EINVAL;

	if (copy_from_user(data, buf, count))
		return -EFAULT;

	data[count + 1] = '\0';
	tok = strsep(&sep, " \n");
	if (kstrtoul(tok, 0, &va))
		return -EINVAL;

	tok = strsep(&sep, " \n");
	if (sep && kstrtoul(tok, 0, &pid))
		return -EINVAL;

	if (sep) {
		tok = strsep(&sep, " \n");
		if (sep && kstrtoul(tok, 0, &flags))
			return -EINVAL;
	}

	if (sep && sep < &data[count])
		return -EINVAL;

	if (flags & PTDUMP_DUMP_PAGE) {
		ret = get_pte_page(pid, va, &pte, &page);
		if (!ret) {
			dump_page(page, "ptedump");
			put_page(page);
		}
	} else {
		ret = get_pte_page(pid, va, &pte, NULL);
	}

	if (!ret) {
		file->private_data = (void *)pte;
		ret = count;
	}

	return ret;
}

static const struct file_operations ptedump_fops = {
	.owner      = THIS_MODULE,
	.open       = ptedump_open,
	.release    = ptedump_release,
	.read       = ptedump_read,
	.write      = ptedump_write
};

static int __init dump_va_page_init(void)
{
	int err;
	dev_t dev;

	printk("Loading PTE dump page module\n");
	err = alloc_chrdev_region(&dev, 0, 1, "ptedump");

	dev_major = MAJOR(dev);

	ptedump_class = class_create(THIS_MODULE, "ptedump");

	/*
	 * Older kernels don't have const struct device so cast to
	 * avoid compiler errors/warnings.
	 */
	*((void **) &ptedump_class->dev_uevent) = ptedump_uevent;

	cdev_init(&cdev, &ptedump_fops);
	cdev.owner = THIS_MODULE;
	cdev_add(&cdev, MKDEV(dev_major, 0), 1);
	device_create(ptedump_class, NULL, MKDEV(dev_major, 0), NULL, "ptedump");

	return 0;
}
module_init(dump_va_page_init);

static void __exit dump_va_page_exit(void)
{
	printk("Dump PTE page module exiting\n");
	device_destroy(ptedump_class, MKDEV(dev_major, 0));
	class_destroy(ptedump_class);
	unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}
module_exit(dump_va_page_exit);
