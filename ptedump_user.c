#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define PTDUMP_DUMP_PAGE (0x1)

unsigned long ptedump_get_pte(void *va)
{
	FILE *ptedump = fopen("/dev/ptedump", "r+");
	unsigned long pte;

	if (!ptedump)
		return -1;

	if (fprintf(ptedump, "0x%lx\n", (unsigned long) va) <= 0) {
		pte = -1;
		goto out;
	}

	if (fscanf(ptedump, "0x%lx\n", &pte) != 1) {
		pte = -1;
		goto out;
	}

out:
	fclose(ptedump);

	return pte;
}

unsigned long ptedump_get_pte_dump_page(void *va)
{
	FILE *ptedump = fopen("/dev/ptedump", "r+");
	unsigned long pte;

	if (!ptedump)
		return -1;

	if (fprintf(ptedump, "0x%lx 0 %d\n", (unsigned long) va, PTDUMP_DUMP_PAGE) <= 0) {
		pte = -1;
		goto out;
	}

	if (fscanf(ptedump, "0x%lx\n", &pte) != 1) {
		pte = -1;
		goto out;
	}

out:
	fclose(ptedump);

	return pte;
}

#ifdef TEST
int main(int argc, char *argv[])
{
	int x = 1;
	unsigned long pte;

	pte = ptedump_get_pte(&x);
	if (pte != -1)
		printf("pte = 0x%lx\n", pte);
	else
		perror("Error");

	if (ptedump_get_pte_dump_page(&x) == -1)
		perror("Error");

	return 0;
}
#endif
