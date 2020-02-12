#ifndef TRANSPILER_ASM_IGRAPH_H
#define TRANSPILER_ASM_IGRAPH_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/* instruction dependency graphs */

/*
instruction dependency graph abstraction

because the (finite) number of registers (and therefore, direct dependencies)
are vastly less than the maximum (infinite) number of instructions,
a linked list approach is used
*/
struct idgraph {
  size_t ecount; /* edge count */
  size_t vcount; /* vertex count */
  struct idgraph_dependents_ll **vertices; /* hash table */
};

/* an instruction, and its dependents */
struct idgraph_dependents_ll {
  struct idgraph_dependent_llnode *head;
  struct instruction *instruction;
  struct idgraph_dependent_llnode *tail;
};

/* linked list of dependent instructions */
struct idgraph_dependent_llnode {
  struct instruction *instruction;
  struct idgraph_dependent_llnode *next;
};

int idgraph_fini(struct igraph *graph);

/* compute a hash of the raw instruction */
static int idgraph__ihash(size_t *dest, struct instruction *instruction);

int idgraph_init(struct igraph *dest, const size_t count,
  const struct instruction **instructions);

/* canonicalize the topological order of the instructions (into an array) */
int idgraph_topology_canonicalize(const struct igraph *graph,
  struct instruction **dest, const size_t destlen);

/*
mutate the topological order of the instructions (into an array),
selecting each instruction via `selector` (array passed is canonicalized)
*/
int idgraph_topology_mutate(const struct igraph *graph,
  struct instruction **dest, const size_t destlen,
  int (*selector)(const struct idgraph *, struct instruction *, const size_t,
    const struct instruction **));

/* randomize the topological order of the instructions (into an array) */
int idgraph_topology_randomize(const struct igraph *graph,
  struct instruction **dest, const size_t destlen);

/* selector for a random topological order */
static int idgraph_topology_randomize__selector(const struct igraph *graph,
  const size_t count, const struct instruction **instructions);

#endif

