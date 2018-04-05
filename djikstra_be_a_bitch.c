#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SELF 0
#define INFINITY -1
#define NONE -1
// distances

typedef struct vertex {
        int id; //own ID
        int dist; // dist from source node
        struct vertex *pre; // pointer to previous node on current shortest path
} vertex; 

typedef struct {
        int dest;
        int next;
} entry;

typedef struct router {
        int id;
        vertex *varray;
        int n; // number of routers on the network
        entry *table;
} router;

typedef struct graph {
        int size;    // number of vertices
        int *adjmtx; // store distances of all nodes
} graph;

// // struct with info about 1 peer
// typedef struct one_peer{
//     uuid_t uuid; // dest node
//     char* name;
//     uint16_t front_port;
//     uint16_t back_port;
//     char* content_dir;
//     int distance;
//     int num_files;
//     char* files[20];       //Max number of files one peer can have is 20 **** MAYBE REVISIT AND MAKE IT DYNAMICALLY ALLOCATE
//     char* host;
//     struct sockaddr_in addr;
//     int last_sent;
//     int last_received;
// } peer, *peer_t;



// TODO: make individual graph for every peer using peer_table
graph *makegraph(int n) {
	if (n <= 0) {
		fprintf(stderr, "Error\n");
		return NULL;
	}
	graph *g = (graph *)calloc(1, sizeof(graph));
	g->size = n;
	g->adjmtx = (int *)calloc(n * n, sizeof(int));
	return g;
}

static int less(int a, int b) {
        return (unsigned)a < (unsigned)b;
}

static vertex *pickMIN(vertex **p, int len) {
        static vertex start = { 0, INFINITY, NULL };

        int i;
        vertex *r;
        vertex *sp = &start;
        vertex **min = &sp;
        for (i = 0; i < len; i++, p++) {
                if (*p == NULL)
                        continue;
                if (less((*p)->dist, (*min)->dist))
                        min = p;
        }
        if (*min == &start)	// all varr have dist==INFINITY
                return NULL;
        // min element is found
        r = *min;
        *min = NULL;
        return r;
}

// direct distance from vertex with id==a to vertex with id==b
static int distance(graph *g, int a, int b) {
        --a;	// id to index; id starts with 1, index starts with 0
        --b;	// id to index
        return *(g->adjmtx + a * g->size + b);
}

void dijkstra(graph *g, int srcid, vertex *varr) {
        int n = g->size;
        vertex **s_set = (vertex **)calloc(n, sizeof(char *));
        vertex **q_set = (vertex **)calloc(n, sizeof(char *));
        int i;

        vertex **p;
        for (i = 1, p = q_set; i < n+1; i++, p++) {
                *p = varr + i - 1;
                if (i == srcid) {
                        (*p)->dist = 0;
                } else {
                        (*p)->dist = INFINITY;
                }
                (*p)->pre = NULL;
        }

        vertex *u;
        int s_set_i = 0;	
        int delta;
        int dist;
        vertex *vp;
        while ((u = pickMIN(q_set, n)) != NULL) {
                *(s_set + s_set_i++) = u;
                // relaxation
                for (i=1, vp=varr; i < n+1; i++, vp++) {
                        if ((delta = distance(g, u->id, i)) == INFINITY) {
                                fflush(stdout);
                                continue;
                        }

                        dist = u->dist + delta;
                        if (less(dist, vp->dist)) {
                                vp->dist = dist;
                                vp->pre = u;
                        }
                }
        }
        free(s_set);
        free(q_set);
}


router *makerouter(int id, int n) {
	router *r = (router *)calloc(1, sizeof(router));
	r->id = id;
	r->n = n;
	r->varray = (vertex *)calloc(n, sizeof(vertex));
	int i;
	for (i = 0; i < n; i++) {
		(r->varray + i)->id = i + 1;
	}
	r->table = (entry *)calloc(n, sizeof(entry));
	return r;
}

void freerouter(router *r) {
	if (r == NULL)
		return;
	free(r->varray);
	free(r->table);
	free(r);
}

void printpath(router *src_router, int dest) {
        int src = src_router->id;
	if (dest == src) {
		printf("The destination router is the source router. No need to go through a path. The total cost is 0.\n");
		return;
	}

        vertex *dest_vtx = src_router->varray + dest - 1;
	if (dest_vtx->dist == INFINITY) {
		printf("The destination router is isolated. No path is found. The total cost is INFINITY.\n");
		return;
	}

	printf("The shortest path from %d to %d is %d", src, dest, src);

        int *sp = (int *) calloc(src_router->n - 1, sizeof(int));
        vertex *vp = dest_vtx;
        assert(dest = vp->id);
        int i = -1, id = dest;
        do {
                sp[++i] = id;
                vp = vp->pre;
                id = vp->id;
        } while (id != src);
        for (; i > -1; i--) {
                printf("-%d", sp[i]);
        }
	printf(", the total cost is %d.\n", dest_vtx->dist);
        free(sp);
}

static int nexthop(router *src, int dest) {
	if (dest == src->id)	// dest is the src router
		return SELF;
	if ((src->varray+dest-1)->dist == INFINITY)	// dest is an isolated vertex in the graph
		return NONE;
	vertex *p = src->varray + dest - 1;
	while (p->pre->id != src->id)
		p = p->pre;
	// p->pre == src
	return p->id;
}

void buildtable(router *r, graph *g) {
	dijkstra(g, r->id, r->varray);//printf("dijkstra ends\n");fflush(stdout);

	int i;
	entry *p;
	for (i=0, p=r->table; i < r->n; i++, p++) {//printf("buildtable for-loop %d\n", i); fflush(stdout);
		p->dest = i + 1;
		p->next = nexthop(r, p->dest);
	}
}



// ~~~~~~~~~~~~~~~ INTEGRATE WITH VODSERVER TODO:

// 1. makegraph from peer_table:
//r = makerouter(tmp, g->size);
			// buildtable(r, g);
			// printf("The routing table for router %d is:\n", r->id);
			// printrouter(r);
			// freerouter(r);
// 2. r = makerouter(fromto[0], g->size);
// 3. call: dijkstra(g, r->id, r->varray);
// 4. print SPF printpath(r, fromto[1]);
