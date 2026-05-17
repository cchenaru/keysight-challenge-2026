#ifndef LIST_H
#define LIST_H
 
#include <stdlib.h>
 
struct thread;

typedef struct node {
	struct node *prev;
	struct node *next;
	struct thread *current;
} Node;
 
typedef struct double_list {
	Node *head;
	Node *tail;
	int node_nr;
} List;


List *initList(void);
 
List *createList(struct thread *value);
 
List *insertFront(List *list, struct thread *value);
 
List *insertRear(List *list, struct thread *value);
 
List *deleteNode(List *list, Node *target);
 
List *freeList(List *list);
 
Node *findNode(List *list, struct thread *value);

#endif
