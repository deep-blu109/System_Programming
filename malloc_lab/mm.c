/* 
 * mm-implicit.c -  Simple allocator based on implicit free lists, 
 *                  first fit placement, and boundary tag coalescing. 
 *
 * Each block has header and footer of the form:
 * 
 *      31                     3  2  1  0 
 *      -----------------------------------
 *     | s  s  s  s  ... s  s  s  0  0  a/f
 *      ----------------------------------- 
 * 
 * where s are the meaningful size bits and a/f is set 
 * iff the block is allocated. The list has the following form:
 *
 * begin                                                          end
 * heap                                                           heap  
 *  -----------------------------------------------------------------   
 * |  pad   | hdr(8:a) | ftr(8:a) | zero or more usr blks | hdr(8:a) |
 *  -----------------------------------------------------------------
 *          |       prologue      |                       | epilogue |
 *          |         block       |                       | block    |
 *
 * The allocated prologue and epilogue blocks are overhead that
 * eliminate edge conditions during coalescing.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "mm.h"
#include "memlib.h"

/*
 * If NEXT_FIT defined use next fit search, else use first fit search 
 */
#define NEXT_FITx



/* $begin mallocmacros */
/* Basic constants and macros */
#define WSIZE       4       /* word size (bytes) */  
#define DSIZE       8       /* doubleword size (bytes) */
#define CHUNKSIZE  (1<<12)  /* initial heap size (bytes) */
#define OVERHEAD    8       /* overhead of header and footer (bytes) */

#define MAX(x, y) ((x) > (y)? (x) : (y))  

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc)  ((size) | (alloc))

/* Read and write a word at address p */
#define GET(p)       (*(size_t *)(p))
#define PUT(p, val)  (*(size_t *)(p) = (val))  

/* Read the size and allocated fields from address p */
#define GET_SIZE(p)  (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp)       ((char *)(bp) - WSIZE)  
#define FTRP(bp)       ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp)  ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp)  ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))
/* $end mallocmacros */

/* Global variables */
static char *_heap_listp;  /* pointer to first block */  
#ifdef NEXT_FIT
static char *rover;       /* next fit rover */
#endif

static int _heap_ext_counter=0;

/* function prototypes for internal helper routines */
static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static void printblock(void *bp); 
static void checkblock(void *bp);

char* get_heap_listp() {
    return _heap_listp;
}
char* set_and_get_heap_listp(char* ptr) {
    _heap_listp = ptr;
    return _heap_listp;
}

/* 
 * mm_init - Initialize the memory manager 
 */
/* $begin mminit */
int mm_init(void) 
{
    /* create the initial empty heap */
    if (set_and_get_heap_listp(mem_sbrk(4*WSIZE)) == (void *)-1)
	return -1;
    PUT(get_heap_listp(), 0);                        /* alignment padding */
    PUT(get_heap_listp()+WSIZE, PACK(OVERHEAD, 1));  /* prologue header */ 
    PUT(get_heap_listp()+DSIZE, PACK(OVERHEAD, 1));  /* prologue footer */ 
    PUT(get_heap_listp()+WSIZE+DSIZE, PACK(0, 1));   /* epilogue header */
    set_and_get_heap_listp(get_heap_listp()+DSIZE);

#ifdef NEXT_FIT
    rover = get_heap_listp();
#endif

    /* Extend the empty heap with a free block of CHUNKSIZE bytes */
    if (extend_heap(CHUNKSIZE/WSIZE) == NULL)
	return -1;
    return 0;
}
/* $end mminit */

/* 주어진 사이즈를 allocating 할 수 있게 수정하는 함수 */
size_t modifySize(size_t size){
	size_t mSize; //바뀌게 될 사이즈
	
	//주어진 사이즈가 (word 사이즈 * 2)보다 작거나 같은 경우
	if(size <= DSIZE){
		// 주어진 사이즈가 0일 경우
                if(size == 0){
                        return NULL;
                }
                mSize = DSIZE + DSIZE; // allocating할 수 있게 변동한 payload의 사이즈 + header, footer을 포함할 사이즈
        }

	//주어진 사이즈가 (word 사이즈 * 2)보다 큰 경우
        else{
                mSize = size;

		// allocating할 수 있게  payload영역의 사이즈 수정
                for(size_t i = 1; i < DSIZE; i++){
                        if(mSize % 8 == 0){
                                break;
                        }
                        mSize++;
                }
                mSize += DSIZE; //allocating할 수 있게 변동한 payload의 사이즈 + header, footer을 포함할 사이즈
		
        }
	return mSize;
}


/* 
 * mm_malloc - Allocate a block with at least size bytes of payload 
 */
/* $begin mmmalloc */
void *mm_malloc(size_t size) 
{
        void *bp; //malloc되는 지점의 포인터
        size_t mallSize = modifySize(size); //malloc되는 크기(modify 함수는 mm_malloc함수 위에 있음)

        bp = find_fit(mallSize); //allocate될 heap 영역을 찾고 해당 공간의 주소 저장

	// bp의 값이 NULL이 아닐 경우(heap에 malloc가능한 공간이 있는 경우) allocate
        if(bp != NULL){ 
                place(bp, mallSize);
                return bp;
        }

	// bp의 값이 NULL인 경우(heap에 malloc가능한 공간이 없는 경우) heap영역 확장 후  확장된 영역의 주소 저장
        bp = extend_heap(mallSize/WSIZE);

	// bp의 값이 NULL인 경우(필요한 크기만큼 heap영역 확장을 할 수 없는 경우) NULL을 return
        if(bp == NULL){
                return NULL;
        }
	//bp의 값이 NULL이 아닌 경우(heap 영을 확장한 경우) 해당 주소에 allocate
        else{
                place(bp, mallSize);
                return bp;
        }
} 
/* $end mmmalloc */

/* 
 * mm_free - Free a block 
 */
/* $begin mmfree */
void mm_free(void *bp)
{
        // 포인터 bp가 가리키는 영역이 malloc되어있는지 확인, malloc 되지 않은 경우 함수 종료
	if(HDRP(bp) && 0x1 == 0){
  		return;
        }

        size_t size = GET_SIZE(HDRP(bp)); // bp가 가르키는 allocated 영역의 크기

	// allocate된 영역을 free시키기
        PUT(HDRP(bp), PACK(size, 0)); //malloc된 영역의 header의 allocated 여부를 0으로 지정
        PUT(FTRP(bp), PACK(size, 0)); //malloc된 영역의 footer의 allocated 여부를 0으로 지정

        coalesce(bp); // free 된 영역의 앞 뒤에 free인 영역이 있는 경우 coalescing 진행

}

/* $end mmfree */

/*
 * mm_realloc - naive implementation of mm_realloc
 */
void *mm_realloc(void *ptr, size_t size)
{	// ptr이 NULL인  경우 size만큼 malloc
        if(ptr == NULL){
                return mm_malloc(size);
        }
	
	// size가 0인 경우 free 영역으로 바꾼
        if(size == 0){
                mm_free(ptr);
		return NULL;         	
	}

        size_t reallsize = modifySize(size); // reallocating될 크기
        size_t oldS = GET_SIZE(HDRP(ptr)); // realloc 되기 전 크기
        void *bp = ptr; // reallocate된 주소의 포인터
        void *nextP = NEXT_BLKP(ptr); // ptr이 가리키는 영역의 다음에 있는 영역의 주소를 가리키는 포인터
        size_t nextS = GET_SIZE(HDRP(nextP)); // ptr이 가리키는 영역의 다음에 있는 영역의 크기

	// realloc되는 크기가 바꾸기 전 크기와 같은 경우 변동 없이 기존 주소의 포인터 출력
        if(reallsize == oldS){
                return bp;
        }
	
	size_t sumS = oldS; // realloc 가능한 공간을 확인하는 걸 보조할 변수
	
	while(1){
		// 다음 영역이 free상태인 경우
		if(!GET_ALLOC(HDRP(nextP))){
			// 이전 영역과 뒤에 있는 영역(들)의 크기가 realloc할 크기보다 작을 경우
			if(sumS + nextS < reallsize){
				sumS += nextS; // 확인된 영역의 크기를 추가
                		nextP = NEXT_BLKP(nextP); // 확인된 영역의 다음 영역을 가리키는 주소값 저장
                		nextS = GET_SIZE(HDRP(nextP)); // 확인된 영역의 다음 영역의 크기 저장
			}

			// 이전 영역과 뒤에 있는 영역(들)의 크기가 realloc할 크기와 같은 경우
			else if(sumS + nextS == reallsize){
				PUT(HDRP(bp), PACK(reallsize, 1)); // realloc할 영역의 header에 사이즈 저장
				PUT(FTRP(nextP), PACK(reallsize, 1)); // realloc할 영역의 footer에 사이즈 저장
				break;
			}

			// 이전 영역과 뒤에 있는 영역(들)의 크기가 realloc할 크기보다 큰 경우
			else{
				PUT(HDRP(bp), PACK(reallsize, 1)); // realloc할 영역의 header에 사이즈 저장
                                PUT(FTRP(bp), PACK(reallsize, 1)); // realloc할 영역의 footer에 사이즈 저장
				PUT(HDRP(NEXT_BLKP(bp)), PACK(sumS + nextS - reallsize, 0)); // realloc된 영역의 다음 영역의 header의 변동된 사이즈 저장
				PUT(FTRP(NEXT_BLKP(bp)), PACK(sumS + nextS - reallsize, 0)); // realloc된 영역의 다음 영역의 footer의 변동된 사이즈 저장
				break;

			}
		}

		//다음 영역이 allocating된 경우(realloc할 공간이 부족이 없을 경우)
		else{
			bp = mm_malloc(size); // 새로운 공간에 malloc
        		memcpy(bp, ptr, oldS - DSIZE);  // 이전 영역의 payload내용을 카피한 후 새롭게 malloc한 곳에 그대로 저장
	        	mm_free(ptr); // 이전 영역을 free상태로 바꿈
        		break;

		}
	}
	
	return bp;
}

/* 
 * mm_checkheap - Check the heap for consistency 
 */
void mm_checkheap(int verbose) 
{
    char *bp = get_heap_listp();

    if (verbose)
	printf("Heap (%p):\n", get_heap_listp());

    if ((GET_SIZE(HDRP(get_heap_listp())) != DSIZE) || !GET_ALLOC(HDRP(get_heap_listp())))
	printf("Bad prologue header\n");
    checkblock(get_heap_listp());

    for (bp = get_heap_listp(); GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
	if (verbose) 
	    printblock(bp);
	checkblock(bp);
    }
     
    if (verbose)
	printblock(bp);
    if ((GET_SIZE(HDRP(bp)) != 0) || !(GET_ALLOC(HDRP(bp))))
	printf("Bad epilogue header\n");
}

/* The remaining routines are internal helper routines */

/* 
 * extend_heap - Extend heap with free block and return its block pointer
 */
/* $begin mmextendheap */
static void *extend_heap(size_t words) 
{
    char *bp;
    size_t size;
    _heap_ext_counter++;
	
    /* Allocate an even number of words to maintain alignment */
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE;
    if ((bp = mem_sbrk(size)) == (void *)-1) 
	return NULL;

    /* Initialize free block header/footer and the epilogue header */
    PUT(HDRP(bp), PACK(size, 0));         /* free block header */
    PUT(FTRP(bp), PACK(size, 0));         /* free block footer */
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* new epilogue header */

    /* Coalesce if the previous block was free */
    return coalesce(bp);
}
/* $end mmextendheap */

/* 
 * place - Place block of asize bytes at start of free block bp 
 *         and split if remainder would be at least minimum block size
 */
/* $begin mmplace */
/* $begin mmplace-proto */
static void place(void *bp, size_t asize)
/* $end mmplace-proto */
{
    size_t csize = GET_SIZE(HDRP(bp));   

    if ((csize - asize) >= (DSIZE + OVERHEAD)) { 
	PUT(HDRP(bp), PACK(asize, 1));
	PUT(FTRP(bp), PACK(asize, 1));
	bp = NEXT_BLKP(bp);
	PUT(HDRP(bp), PACK(csize-asize, 0));
	PUT(FTRP(bp), PACK(csize-asize, 0));
    }
    else { 
	PUT(HDRP(bp), PACK(csize, 1));
	PUT(FTRP(bp), PACK(csize, 1));
    }
}
/* $end mmplace */

/* 
 * find_fit - Find a fit for a block with asize bytes 
 */
static void *find_fit(size_t asize)
{
#ifdef NEXT_FIT 
    /* next fit search */
    char *oldrover = rover;

    /* search from the rover to the end of list */
    for ( ; GET_SIZE(HDRP(rover)) > 0; rover = NEXT_BLKP(rover))
	if (!GET_ALLOC(HDRP(rover)) && (asize <= GET_SIZE(HDRP(rover))))
	    return rover;

    /* search from start of list to old rover */
    for (rover = get_heap_listp(); rover < oldrover; rover = NEXT_BLKP(rover))
	if (!GET_ALLOC(HDRP(rover)) && (asize <= GET_SIZE(HDRP(rover))))
	    return rover;

    return NULL;  /* no fit found */
#else 
    /* first fit search */
    void *bp;

    for (bp = get_heap_listp(); GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
	if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) {
	    return bp;
	}
    }
    return NULL; /* no fit */
#endif
}

/*
 * coalesce - boundary tag coalescing. Return ptr to coalesced block
 */
static void *coalesce(void *bp) 
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc) {            /* Case 1 */
	return bp;
    }

    else if (prev_alloc && !next_alloc) {      /* Case 2 */
	size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size,0));
    }

    else if (!prev_alloc && next_alloc) {      /* Case 3 */
	size += GET_SIZE(HDRP(PREV_BLKP(bp)));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
	bp = PREV_BLKP(bp);
    }

    else {                                     /* Case 4 */
	size += GET_SIZE(HDRP(PREV_BLKP(bp))) + 
	    GET_SIZE(FTRP(NEXT_BLKP(bp)));
	PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
	PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
	bp = PREV_BLKP(bp);
    }

#ifdef NEXT_FIT
    /* Make sure the rover isn't pointing into the free block */
    /* that we just coalesced */
    if ((rover > (char *)bp) && (rover < NEXT_BLKP(bp))) 
	rover = bp;
#endif

    return bp;
}


static void printblock(void *bp) 
{
    size_t hsize, halloc, fsize, falloc;

    hsize = GET_SIZE(HDRP(bp));
    halloc = GET_ALLOC(HDRP(bp));  
    fsize = GET_SIZE(FTRP(bp));
    falloc = GET_ALLOC(FTRP(bp));  
    
    if (hsize == 0) {
	printf("%p: EOL\n", bp);
	return;
    }

    printf("%p: header: [%d:%c] footer: [%d:%c]\n", bp, 
	   hsize, (halloc ? 'a' : 'f'), 
	   fsize, (falloc ? 'a' : 'f')); 
}

static void checkblock(void *bp) 
{
    if ((size_t)bp % 8)
	printf("Error: %p is not doubleword aligned\n", bp);
    if (GET(HDRP(bp)) != GET(FTRP(bp)))
	printf("Error: header does not match footer\n");
}


