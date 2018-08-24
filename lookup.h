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
/* ���ʾ���һ������                                                       */
/************************************************************************/
#include <windows.h>

// �ڲ����ҽṹ
typedef struct _lookup_internal_t {
    CRITICAL_SECTION cs;
    void *root;
} lookup_t;

// ʵ��ڵ�ṹ������ڵ㣩
typedef struct _entry_t {
	struct _entry_t *next;	// ��һ���ڵ�
	ULONG_PTR id;			// ��ǰ�ڵ��id
	unsigned int size;		// �ڵ����ݴ�С
	unsigned char data[0];	// ���ݴ��
} entry_t;


void lookup_init(lookup_t *d);

// ����������һ���ڵ㣨ָ��id�������������ڵ����ݴ��ָ��
void *lookup_add(lookup_t *d, ULONG_PTR id, unsigned int size);

// ����ָ��id�Ľڵ��������
void *lookup_get(lookup_t *d, ULONG_PTR id, unsigned int *size);

// ��������ɾ��ָ��id�Ľڵ�
void lookup_del(lookup_t *d, ULONG_PTR id);

void *lookup_add_no_cs(lookup_t *d, ULONG_PTR id, unsigned int size);
void *lookup_get_no_cs(lookup_t *d, ULONG_PTR id, unsigned int *size);
void lookup_del_no_cs(lookup_t *d, ULONG_PTR id);
