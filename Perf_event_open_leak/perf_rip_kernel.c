#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/perf_regs.h>
#include <sys/utsname.h>
#include <signal.h>

#define PAGE_SIZE 0x1000
#define DATE_SIZE PAGE_SIZE
#define MMAP_SIZE (PAGE_SIZE + DATE_SIZE)
#define MASK 0xffffff

int perf_event_open(struct perf_event_attr *attr,
                   pid_t pid, 
                   int cpu, 
                   int group_fd, 
                   unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr,
                   pid,  cpu,  group_fd,   flags);
}

struct __attribute__((packed)) my_sample{
	struct perf_event_header header;
	uint64_t ip;
};

int main(){
	struct perf_event_attr pe;
	int fd = -1;
	pid_t child = 0;

	switch ((child = fork())) {
	case -1:
		fprintf(stderr, "fork failed: %m\n");
		return -1;
	case 0:;
		int id = 0;
		while (1) id = getuid();
		return 1;
	default:
		break;
	}

	memset(&pe, 0, sizeof(pe));
	pe.size = sizeof(pe);
	pe.type = PERF_TYPE_SOFTWARE;
	pe.config = PERF_COUNT_SW_TASK_CLOCK;
	pe.disabled = 1;
	pe.exclude_user = 1;
	pe.exclude_hv = 1;
	pe.sample_type = PERF_SAMPLE_IP;
	pe.sample_period = 10;
	pe.precise_ip = 1;

	fd = perf_event_open(&pe, child, -1, -1, 0);
	if(fd == -1){
		printf("failed to perf_event_open!\n");
		return -1;
	}

	// get sampled data
	struct perf_event_mmap_page* mpage = mmap(
			0, MMAP_SIZE, PROT_READ|PROT_WRITE,
			MAP_SHARED, fd, 0 
		);
	if(mpage == MAP_FAILED){
		printf("failed to create perf_event_mmap_page!\n");
		return -1;
	}

	// enable event
	if(ioctl(fd, PERF_EVENT_IOC_ENABLE)){
		printf("failed to enable event!\n");
		return -1;
	}

	char* data_page = ((char* )mpage) + PAGE_SIZE;

	size_t progres = 0;
	size_t last_head = 0;
	size_t min = ~0;
	int sample_counts = 0;
	struct my_sample* cur = NULL;

	while(sample_counts < 50){
		// wait for new data
		while(mpage->data_head == last_head);

		last_head = mpage->data_head;

		while(progres < last_head){
			cur = (struct sample*)(data_page + progres % DATE_SIZE);
			switch(cur->header.type){
				case PERF_RECORD_SAMPLE:
					sample_counts += 1;
					if(cur->header.size < sizeof(*cur)){
						printf("size too small!\n");
						return -1;
					}
					uint64_t prefix = (cur->ip);
					// find min address
					if(prefix < min){
						min = prefix;
					}
					break;
			case PERF_RECORD_THROTTLE:
			case PERF_RECORD_UNTHROTTLE:
			case PERF_RECORD_LOST:
				break;
			default:
				fprintf(stderr,
                                        "unexpected event: %x\n",
                                        cur->header.type);
				return -1;
			}
			progres += cur->header.size;

		}
		// tell kernel, we have read it, reflect last read
		mpage->data_tail = last_head;
	}

	printf("minize address: 0x%llx\n", min);
}