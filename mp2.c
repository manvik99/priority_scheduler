#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <uapi/linux/sched/types.h>
#include "mp2_given.h"
#include<linux/kthread.h>

// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Manvik Nanda <mbnanda2@illinois.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CS-423 MP2");

// Define a slab 
static struct kmem_cache *mp2_task_cache;

// Initialize List Head
static LIST_HEAD(mp2_task_list);

/* Macro Definitions */
#define DEBUG 1
#define REGISTRATION 'R'
#define YIELD 'Y'
#define DE_REGISTRATION 'D'
#define READY 2
#define SLEEPING 3
#define RUNNING 4

/* Definining PCB */
struct mp2_task_struct {
	unsigned long period;
	unsigned long computation;
	int pid;
	int state;
    struct task_struct* linux_task; 
    struct timer_list wakeup_timer; 
	struct list_head mylist;
};

// Keeping track of current task
struct mp2_task_struct* mp2_current = NULL;

// Declaring the global dispatching thread
static struct task_struct *dispatch_thread;

// wake up timer
static void wake_up_timer_callback(struct timer_list *t){
	struct mp2_task_struct *task;
	printk("wake_up_timer_callback\n");
	task = from_timer(task, t, wakeup_timer);
    task->state = READY; // Change state of the task to READY

	mod_timer(&task->wakeup_timer, jiffies + msecs_to_jiffies(task->period));
    // Wake the dispatching thread

    wake_up_process(dispatch_thread);
}

static void registration(int pid, int period, int computation){
	struct mp2_task_struct *new_task;
	struct task_struct *task = find_task_by_pid(pid);
	int ret;
	
	// Allocate memory for the new task
    new_task = kmem_cache_alloc(mp2_task_cache, GFP_KERNEL);
    if (!new_task) {
        printk(KERN_ERR "MP2: Failed to allocate memory for task\n");
        return;
    }

	// Initialize the new task
    new_task->pid = pid;
    new_task->linux_task = task;
    new_task->period = period;
    new_task->computation = computation;
    new_task->state = SLEEPING;

	// Add timer to the list
	timer_setup(&new_task->wakeup_timer, wake_up_timer_callback, 0);
	ret = mod_timer(&new_task->wakeup_timer, jiffies + msecs_to_jiffies(period));
	if (ret)
		pr_err("%s: Timer firing failed\n", __func__);

    // Insert into task list
    list_add(&new_task->mylist, &mp2_task_list);


	// // For printining the linked list. 
	// struct mp2_task_struct *entry;
	// struct list_head *pos_iter;
	// list_for_each(pos_iter, &mp2_task_list) {
	// 	entry = list_entry(pos_iter, struct mp2_task_struct, mylist);
	// 	printk("in registration %d --> %lu\n", entry->pid, entry->period);
	// }
}

static void task_yield(int pid){
	printk("YIELD\n");
}

static void de_registration(int pid){
	struct mp2_task_struct *tmp, *next;
	int curr_process_pid;
	list_for_each_entry_safe(tmp, next, &mp2_task_list, mylist) {
		curr_process_pid = tmp->pid;
		if (curr_process_pid == pid) {
			list_del(&tmp->mylist);
			kfree(tmp);
		}
	}

	// // Clear the linux->task state. 
	// struct mp2_task_struct *task = find_task_by_pid(pid);

    // if (task) {
    //     del_timer_sync(&task->wakeup_timer);
    //     kmem_cache_free(mp2_task_cache, task);
    // }
}

/* Implementing the Proc File */
#define PROC_DIRNAME "mp2"
#define PROC_FILENAME "status"
struct proc_dir_entry *my_proc_dir;
struct proc_dir_entry *my_proc_file;

static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) {
	int pid, period, computation; 
	char *kbuf, state;

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	kbuf[count] = '\0';
	if(copy_from_user(kbuf,ubuf,count))
		return -EFAULT;
	
	state = kbuf[0];
	switch (state)
	{
	case REGISTRATION:
		sscanf(kbuf, "%c,%d,%d,%d", &state, &pid, &period, &computation);
		registration(pid, period, computation);
		break;
	case YIELD:
		sscanf(kbuf, "%c,%d", &state, &pid);
		task_yield(pid);
		break;
	case DE_REGISTRATION:
		sscanf(kbuf, "%c,%d", &state, &pid);
		de_registration(pid);
		break;
	
	default:
		printk("Invalig Arguments!\n");
	}
	kfree(kbuf);
	return count;
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) {
	struct mp2_task_struct *entry;
    struct list_head *pos_iter;
    char *output_buffer;
    size_t output_size = 0;
    ssize_t ret;

    // Calculate the output size needed
    list_for_each(pos_iter, &mp2_task_list) {
        entry = list_entry(pos_iter, struct mp2_task_struct, mylist);
        output_size += snprintf(NULL, 0, "%d: %lu\n", entry->pid, entry->period);
    }

    // Allocate memory for the output buffer
    output_buffer = kmalloc(output_size + 1, GFP_KERNEL);
    if (!output_buffer) {
        return -ENOMEM;
    }

    // Fill the output buffer with the process data
    output_buffer[0] = '\0';
    list_for_each(pos_iter, &mp2_task_list) {
        entry = list_entry(pos_iter, struct mp2_task_struct, mylist);
        snprintf(output_buffer + strlen(output_buffer), output_size - strlen(output_buffer), 
                 "%d: %lu\n", entry->pid, entry->period);
    }

    // Copy the output buffer to user space
    ret = simple_read_from_buffer(ubuf, count, ppos, output_buffer, output_size);
    
    kfree(output_buffer); // Free the allocated memory
    return ret;
}
static struct proc_ops myops = 
{
	.proc_read = myread,
	.proc_write = mywrite,
};

// dispatch_thread_fn
static int dispatch_thread_fn(void* data){
	struct mp2_task_struct *task, *highest_priority_task;
	struct sched_attr attr;
	printk("in dispatch_thread_fn\n");
	while(!kthread_should_stop()){
		// Set the state of the thread dispatch_thread_fn to be sleeping, till a task is there to be executed. 
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();

		highest_priority_task = NULL;
		// Find the highest priority task in Ready State
		list_for_each_entry(task, &mp2_task_list, mylist){
			if (task -> state == READY){
				if (!highest_priority_task){
					highest_priority_task = task;
				}
				else if (task -> period < highest_priority_task -> period){
					highest_priority_task = task;
				}		
			}
		}
		if(!highest_priority_task) // Continue waiting if no highest priority task
			continue;
		
		if (mp2_current && mp2_current->state == RUNNING){
			if(mp2_current->period < highest_priority_task->period){
				continue;
			}
			else{
				// Schedule the highest_priority_task, highest_priority_task.state = RUNNING, current_running_task.state = READY
				// de-schedule the current task
				attr.sched_policy = SCHED_NORMAL;
				attr.sched_priority = 0;
				sched_setattr_nocheck(mp2_current->linux_task, &attr);
			}
		}

		// Schedule the highest_priority_task
		mp2_current = highest_priority_task;
		mp2_current->state = RUNNING;
		wake_up_process(mp2_current->linux_task);
		attr.sched_policy = SCHED_FIFO;
		attr.sched_priority = 99;
		sched_setattr_nocheck(mp2_current->linux_task, &attr);
	}
	return 0;
}

// mp2_init - Called when module is loaded
int __init mp2_init(void){
	#ifdef DEBUG
		printk(KERN_ALERT "MP2 MODULE LOADING\n");
	#endif
	
	/* Creating a proc file */ 
	my_proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	if(!my_proc_dir){
		printk("Failed to create directory /proc/%s", PROC_DIRNAME);
		return -ENOMEM;
	}
	my_proc_file = proc_create(PROC_FILENAME, 0666 , my_proc_dir, &myops);
	if(!my_proc_file){
		printk("Failed to create file /proc/%s/%s", PROC_FILENAME, PROC_DIRNAME);
		return -ENOMEM;
	}
	printk(KERN_DEBUG "Created file /proc/%s/%s", PROC_DIRNAME, PROC_FILENAME);

	// Allocate a slab 
	mp2_task_cache = kmem_cache_create("mp2_task_cache", sizeof(struct mp2_task_struct), 0, SLAB_PANIC, NULL);
	if (!mp2_task_cache) {
        printk(KERN_ERR "MP2: Failed to create slab cache\n");
        return -ENOMEM;
    }

	dispatch_thread = kthread_run(dispatch_thread_fn, NULL, "mp2_dispatch_thread");
    if (IS_ERR(dispatch_thread)) {
        printk(KERN_ERR "Failed to create dispatching thread\n");
        return PTR_ERR(dispatch_thread);
    }
	
	printk(KERN_ALERT "MP2 MODULE LOADED\n");
	return 0;
}

// mp2_exit - Called when module is unloaded
void __exit mp2_exit(void){
	struct mp2_task_struct *tmp, *next;

	#ifdef DEBUG
		printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
	#endif
	
	proc_remove(my_proc_file);
	proc_remove(my_proc_dir);

	printk(KERN_ALERT "MP2 MODULE UNLOADED\n");

	// Free up the linked list 
	list_for_each_entry_safe(tmp, next, &mp2_task_list, mylist){
		list_del(&tmp->mylist);
		kfree(tmp);
	}
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);
