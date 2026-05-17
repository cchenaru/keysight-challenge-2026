#include <stdio.h>
#include <stdlib.h>
 
#include "list.h"
#include "threads.h"

static Node *createNode(struct thread *value) {
	Node *node = malloc(sizeof(*node));
	if (!node)
		return NULL;
 
	node->prev = NULL;
	node->next = NULL;
	node->current = value;
 
	return node;
}
 
List *initList(void) {
	List *list = malloc(sizeof(*list));
	if (!list)
		return NULL;
 
	list->head = NULL;
	list->tail = NULL;
 
	return list;
}

List *createList(struct thread *value) {
	List *list = initList();
	if (!list)
		return NULL;
 
	Node *node = createNode(value);
	if (!node) {
		free(list);
		return NULL;
	}
 
	list->head = node;
	list->tail = node;
 
	return list;
}

List *insertFront(List *list, struct thread *value) {
	if (!list)
		return createList(value);
 
	Node *node = createNode(value);
	if (!node)
		return list;
 
	if (!list->head) {
		list->head = list->tail = node;
		return list;
	}
 
	node->next = list->head;
	list->head->prev = node;
	list->head = node;
 
	return list;
}
 
List *insertRear(List *list, struct thread *value) {
	if (!list)
		return createList(value);
 
	Node *node = createNode(value);
	if (!node)
		return list;
 
	if (!list->tail) {
		list->head = list->tail = node;
		return list;
	}
 
	node->prev = list->tail;
	list->tail->next = node;
	list->tail = node;
 
	return list;
}

List *deleteNode(List *list, Node *target) {
	if (!list || !target)
		return list;
 
	if (target == list->head)
		list->head = target->next;
 
	if (target == list->tail)
		list->tail = target->prev;
 
	if (target->prev)
		target->prev->next = target->next;
 
	if (target->next)
		target->next->prev = target->prev;
 
	free(target);
 
	if (!list->head)
		list->tail = NULL;
 
	return list;
}

List *freeList(List *list) {
	if (!list)
		return NULL;
 
	Node *curr = list->head;
	Node *tmp;
 
	while (curr) {
		tmp = curr;
		curr = curr->next;
 
		free(tmp);
	}
 
	free(list);
	return NULL;
}

Node *findNode(List *list, struct thread *value) {
	if (!list)
		return NULL;
	
	Node *curr = list->head;

	while (curr) {
		if (curr->current == value)
			return curr;
		curr = curr->next;
	}

	return NULL;
}
