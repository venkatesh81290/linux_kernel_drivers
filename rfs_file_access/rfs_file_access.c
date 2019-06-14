#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

static int __init file_read_init(void)
{
    struct file *f;
    char buf[128];
    mm_segment_t fs;
    int i;
    
    for(i = 0; i < 128; i++)
        buf[i] = 0;
    
    printk(KERN_INFO "file_kernel_read :: Init\n");
    
    f = filp_open("/tmp/test.conf", O_RDONLY, 0);
    if(f == NULL) {
        printk(KERN_ALERT "filp_open error!!.\n");
    } else{
        // Get current segment descriptor
        fs = get_fs();
        // Set segment descriptor associated to kernel space
        set_fs(get_ds());
        // Read the file
        f->f_op->read(f, buf, 128, &f->f_pos);
        // Restore segment descriptor
        set_fs(fs);
        // See what we read from file
        printk(KERN_INFO "buf:%s\n",buf);
    
        filp_close(f,NULL);
    }
    return 0;
}

static void __exit file_read_exit(void)
{
    printk(KERN_INFO "file_kernel_read :: Exit\n");
}

module_init(file_read_init);
module_exit(file_read_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Venkatesh Parthasarathy <venkatesh81290@gmail.com>");
MODULE_DESCRIPTION("Sample File Access Driver");
