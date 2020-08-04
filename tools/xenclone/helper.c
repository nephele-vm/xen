/******************************************************************************
 * Copyright (c) 2020 Costin Lupu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stdio.h>
#include <xen/clone.h>

#define PAGE_SIZE 4096

static int pages_num_to_entries_num(int pages_num)
{
	int entries_num, clz;

	entries_num =
        (PAGE_SIZE * pages_num - sizeof(clone_notification_ring_header_t)) /
        sizeof(clone_notification_t);
    clz = __builtin_clzl(entries_num) + 1;
    /* entries_num is a power of two */
    entries_num = 1 << (64 - clz);

    return entries_num;
}

static void print_ring_sizes(void)
{
	int entries_num, prev_entries_num = 0;

	for (int i = 1; i < 200; i++) {
		entries_num = pages_num_to_entries_num(i);
		if (entries_num != prev_entries_num)
			printf("pages_num=%d -> entries_num=%d\n", i, entries_num);
		prev_entries_num = entries_num;
	}
}


int main(void)
{
	print_ring_sizes();
	return 0;
}
