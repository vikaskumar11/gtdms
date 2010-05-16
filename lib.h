#include <signal.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <assert.h>
#include <evpath.h>
#include <string.h>
#include <pthread.h>
#include <glibtop.h>
#include <glibtop/cpu.h>
#include <glibtop/mem.h>
#include <glibtop/proclist.h>
#include <glibtop/swap.h>
#include <glibtop/uptime.h>
#include <glibtop/loadavg.h>
#include <glibtop/netload.h>
#include <glibtop/mountlist.h>
#include <glibtop/fsusage.h>

#define OPEN_THREAD_LOG_FILE()						\
  do									\
    {									\
      char thread_log_filename[50];					\
      FILE* thread_log;							\
      sprintf (thread_log_filename, "%s%ld.log", __FUNCTION__,(int) pthread_self ()); \
      thread_log = fopen (thread_log_filename, "w");			\
      pthread_setspecific (log_key, thread_log);			\
    }while(0)

#define PRN(X ...)							\
  do									\
    {									\
      Log = (FILE*) pthread_getspecific(log_key);			\
      fprintf(Log, "[%s %s %d] ",__FILE__,__FUNCTION__, __LINE__); fprintf(Log, X); \
      fflush(Log);							\
    }while(0) 

#define FFLUSH(X) //do { if(0 != fflush(NULL)) {perror("fflush"); exit(1);} } while(0)

#define KEY_LEN (20)
#define KEY_HEX_LEN (20 * 2 + 1)
#define ADDRESS_LEN 32
#define NUM_FINGER_TABLE_ELEMENT KEY_LEN * 8
#define TIME_TO_SLEEP 6
#define QUEUE_SIZE 10
#define NUM_THREADS 10
#define TRUE 1
#define FALSE 0
#define NAME_MAX_LEN 128
#define VALUE_MAX_LEN 2048
#define MAX_NUM_RECORD 100
#define DEFAULT_HASH_SIZE 100

typedef struct _hash_bucket{
  struct _hash_bucket *next;
  unsigned char *name;
  unsigned char *value;
}hash_bucket;

typedef struct _hash_table{
  int hash_count;
  hash_bucket *buckets [DEFAULT_HASH_SIZE];
  char *key[DEFAULT_HASH_SIZE];
}hash_table;

typedef struct _Record{
     char name[NAME_MAX_LEN];
     char value[VALUE_MAX_LEN];
}Record;

typedef struct _List{
     Record record[MAX_NUM_RECORD];
     int index;
}List;

typedef struct _Finger{
  char start[KEY_HEX_LEN];
  char successor_key[KEY_HEX_LEN];
  char successor_address[32]; 
}Finger;

typedef struct _FingerTable{
  Finger finger[NUM_FINGER_TABLE_ELEMENT];
  char node_key[KEY_HEX_LEN];
  char node_address[ADDRESS_LEN];
  char predecessor_key[KEY_HEX_LEN];
  char predecessor_address[32];
}FingerTable;

typedef enum _Function_Type {
     Find_Successor,
     Get_Successor,
     Get_Predecessor,
     Set_Predecessor,
     Closest_Preceding_Finger,
     Update_Finger_Table,
     Log_Finger_Table,
     Put_Data,
     Get_Data,
     Check_Update_Predecessor
}Function_Type;

typedef enum _Request_Response_Type {
     Request,
     Response
}Request_Response_Type;

typedef struct _simple_rec {
     Request_Response_Type request_response_type;
     Function_Type function_type;
     char* function_name;
     int index;
     char* key;
     char* address;
     char* name;
     char* value;
     unsigned long int thread_id;
}simple_rec, *simple_rec_ptr;

static FMField simple_field_list[] =
{
     {"request_response_type", "integer", sizeof(int), FMOffset(simple_rec_ptr, request_response_type)},
     {"function_type", "integer", sizeof(int), FMOffset(simple_rec_ptr, function_type)},
     {"function_name", "string", sizeof(char*), FMOffset(simple_rec_ptr, function_name)},
     {"index", "integer", sizeof(int), FMOffset(simple_rec_ptr, index)},
     {"key", "string", sizeof(char*), FMOffset(simple_rec_ptr, key)},
     {"address", "string", sizeof(char*), FMOffset(simple_rec_ptr, address)},
     {"name", "string", sizeof(char*), FMOffset(simple_rec_ptr, name)}, 
     {"value", "string", sizeof(char*), FMOffset(simple_rec_ptr, value)},
     {"thread_id", "integer", sizeof(unsigned long int), FMOffset(simple_rec_ptr, thread_id)},
     {NULL, NULL, 0, 0}
};

static FMStructDescRec simple_format_list[] =
{
     {"simple", simple_field_list, sizeof(simple_rec), NULL},
     {NULL, NULL}
};

typedef struct _Queue{
  simple_rec request_data[QUEUE_SIZE];
  int front;
  int rear;
}Queue;

/*DHT related key functions*/
void key_compute(const char* msg, char* key);
int key_compare(const char* key1, const char* key2);
void key_set(char* key1, const char* key2);
void key_k_start(char* key_k,const char* key, unsigned int k);
void key_k_dec(char* key_k,const char* key, unsigned int k);

/*DHT fingure table related functions*/
void log_finger_table();
void Send(simple_rec_ptr data, char* addr);
void join(char* node_address, char* existing_node_address);
void init_finger_table(char* node_address, char* existing_node_address);
void find_successor(char* key, char* successor_key, char* successor_address);
void find_predecessor(char* key, char* predecessor_key, char* predecessor_address);
void update_others();
void update_finger_table(char* new_node_key, char* new_node_address, int i);
void closest_preceding_finger(char* key, char* next_node_key, char* next_node_address);
void get_successor(char* successor_key, char* successor_address);
void get_predecessor(char* predecessor_key, char* predecessor_address);
void set_predecessor(char* node_key, char* node_address);
void check_update_predecessor(char *request_node_key, char *request_node_address);

/*Queue functions*/
int isEmpty(Queue *q);
int isFull(Queue *q);
void enQueue(Queue *q, simple_rec_ptr request_data_ptr);
void deQueue(Queue * q, simple_rec_ptr request_data_ptr);
void initQueue(Queue *q);

/*Hash functions*/
hash_table* new_hash_table();
void update_add_hash (hash_table* table, char* key, char* name, char* value);
void delete_hash_entry (hash_table* table);
void hash_lookup (hash_table* table, char* key, char* name, char* value);

/*other functions */
void put_data(hash_table* table, char* key, char *name, char* value);
void get_data(hash_table* table, char* key, char* name, char* value);
void store_data(char* name, unsigned long value);
void store_string_data(char* name, char* value);
