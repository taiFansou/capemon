#pragma once
/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/************************************************************************/
/* 本质就是一个链表                                                       */
/************************************************************************/
#include <windows.h>

// 内部查找结构
typedef struct _lookup_internal_t {
    CRITICAL_SECTION cs;
    void *root;
} lookup_t;

// 实体节点结构（链表节点）
typedef struct _entry_t {
	struct _entry_t *next;	// 下一个节点
	ULONG_PTR id;			// 当前节点的id
	unsigned int size;		// 节点数据大小
	unsigned char data[0];	// 数据存放
} entry_t;


void lookup_init(lookup_t *d);

// 在链表增加一个节点（指定id），返回新增节点数据存放指针
void *lookup_add(lookup_t *d, ULONG_PTR id, unsigned int size);

// 返回指定id的节点的数据域
void *lookup_get(lookup_t *d, ULONG_PTR id, unsigned int *size);

// 在链表中删除指定id的节点
void lookup_del(lookup_t *d, ULONG_PTR id);

void *lookup_add_no_cs(lookup_t *d, ULONG_PTR id, unsigned int size);
void *lookup_get_no_cs(lookup_t *d, ULONG_PTR id, unsigned int *size);
void lookup_del_no_cs(lookup_t *d, ULONG_PTR id);
