#include "lib.h"

extern FingerTable ft;
extern simple_rec response_data;
extern CManager cm;
extern int wait;
extern FILE* Log;
extern pthread_key_t log_key;
extern List list;
extern hash_table* table;
extern  pthread_mutex_t m_send_func;
extern pthread_mutex_t m_response;
extern pthread_cond_t c_serve_response;
extern pthread_mutex_t m_hash_table;
extern pthread_mutex_t m_finger_table;

hash_table *new_hash_table ()
{
     PRN("enter\n");

     hash_table *rv = (hash_table*) malloc (sizeof(hash_table));
     assert(NULL != rv);
     memset (rv, 0, sizeof(hash_table));

     PRN("exit\n");
     return rv;
}

static int do_hash (char *name,int len, int size)
{
     PRN("enter\n");

     register int accum = 0;
     register unsigned char *s = name;
     int i = len;

     while (i--) {
	  /* Add the character in... */
	  accum += *s++;
	  /* Add carry back in... */
	  while (accum > 255)
	       accum = (accum & 255) + (accum >> 8);
     }

     PRN("exit\n");
     return accum % size;
}

void update_add_hash (hash_table* table, char* key, char* name, char* value)
{
     PRN("enter\n");
     assert(NULL != table);
     assert(NULL != key);
     assert(NULL != name);
     assert(NULL != value);

     int hashno;
     hash_bucket *bp;     

     hashno = do_hash (key, strlen(key), table -> hash_count);

     if(EBUSY == pthread_mutex_trylock(&m_hash_table))
       return;
     PRN("locked\n");

     /*Search for existing name, update its value and retrun*/
     for(bp = table -> buckets [hashno]; bp; bp = bp -> next)
     {
	  if( 0 == strcmp(name, bp -> name))
	  {
	       if(strlen(bp->value) < strlen(value))
	       {
		    bp->value = realloc(bp->value, strlen(value) + 1);
		    assert(NULL != bp->value);
	       }

	       strcpy(bp -> value, value);
	       pthread_mutex_unlock(&m_hash_table);
	       PRN("unlocked\n");
	       PRN("exit\n");
	       return;
	  }
     }

     /*else create new name-value pair*/
     if(NULL == table -> buckets [hashno])
     {
	  table -> key [hashno] = (char*)malloc(sizeof(char) * strlen(key) + 1);
	  assert(NULL != table ->key [hashno]);
	  strcpy(table -> key [hashno], key);
     }

     bp = (hash_bucket*) malloc(sizeof(hash_bucket));
     assert(NULL != bp);
     bp -> name = (char*)malloc(sizeof(char) * strlen(name) + 1);
     bp -> value = (char*)malloc(sizeof(char)* strlen(value) + 1);
     assert(NULL != bp -> name);
     assert(NULL != bp -> value);

     strcpy(bp -> name, name);
     strcpy(bp -> value, value);;
     bp -> next = table -> buckets [hashno];
     table -> buckets [hashno] = bp;
     pthread_mutex_unlock(&m_hash_table);
     PRN("unlocked\n");
     PRN("exit\n");
}



void hash_lookup (hash_table* table, char* key, char* name, char* value)
{
     PRN("enter\n");

     assert(NULL != table);
     assert(NULL != name);
     assert(NULL != value);

     int hashno;
     hash_bucket *bp;
     int len=0;
     char buff[512]="";

     memset(value, 0, VALUE_MAX_LEN);
     pthread_mutex_lock(&m_hash_table);
     PRN("locked\n");

     if(key)
     {
	  PRN("inside key\n");
	  hashno = do_hash (key, strlen(key), table -> hash_count);
	  for (bp = table -> buckets [hashno]; bp; bp = bp -> next) 
	  {
	       PRN("inside for\n");
	       if (0 == strcmp (bp -> name, name))
	       {
		    //printf("value = [%s]\n", bp -> value);
		    sprintf(value, "%s %s\n", table->key[hashno], bp->value);
		    pthread_mutex_unlock(&m_hash_table);
		    PRN("unlocked\n");
		    return;
	       }
	  }	  
     }

     for(hashno=0; hashno < table -> hash_count; hashno++)
     {
	  PRN("inside for hashno\n");
	  for (bp = table -> buckets [hashno]; bp; bp = bp -> next) 
	  {
	       PRN("inside for bp\n");
	       
	       if (0 == strcmp (bp -> name, name))
	       {
		    //printf("value = [%s]\n", bp -> value);
		    len = len + strlen(table->key[hashno]) + strlen(bp->value);
		    assert(len <= VALUE_MAX_LEN);
		    sprintf(buff, "key[%s] value[%s] ", table->key[hashno], bp->value);
		    strcat(value, buff);
	       }
	  }
     }
     pthread_mutex_unlock(&m_hash_table);
     PRN("unlocked\n");
     PRN("final value=[%s]\n", value);
     PRN("exit\n");
}

void hash_dump (hash_table* table)
{
     PRN("enter\n");
     int i;
     hash_bucket *bp;

     assert(NULL != table);
     PRN("waiting for lock\n");
     pthread_mutex_lock(&m_hash_table);
     PRN("locked\n");
     PRN("got lock\n");

     for (i = 0; i < table -> hash_count; i++) 
     {
	  if (!table -> buckets [i])
	       continue;

	  printf("hash bucket [%d] key [%s]\n", i, table -> key[i]);
	  for (bp = table -> buckets [i]; bp; bp = bp -> next) 
	  {
	       printf("\t[%s] [%s]\n", bp -> name, bp -> value);
	  }
     }
     pthread_mutex_unlock(&m_hash_table);
     PRN("unlocked\n");
     PRN("exit\n");
}

void key_compute(const char* msg, char* key)
{
     //PRN("enter\n");
     assert(NULL != msg);
     assert(NULL != key);

     /* Length of message to encrypt */
     int msg_len = strlen( msg );

     /* output sha1 hash - this will be binary data */
     unsigned char key_tmp[ KEY_LEN ];

     char *p = key;

     /* calculate the SHA1 digest. This is a bit of a shortcut function
      * most gcrypt operations require the creation of a handle, etc. */
     gcry_md_hash_buffer( GCRY_MD_SHA1, key_tmp, msg, msg_len );

     /* Convert each byte to its 2 digit ascii
      * hex representation and place in out */
     int i;
     for ( i = 0; i < KEY_LEN; i++, p += 2 ) {
          snprintf ( p, 3, "%02x", key_tmp[i] );
     }
     //PRN("exit\n");
}

int key_compare(const char* key1, const char* key2)
{
     //PRN("enter\n");
     assert(NULL != key1);
     assert(NULL != key2);
     
     mpz_t op1, op2;
     if(-1 == mpz_init_set_str(op1, key1, 16))
     {
	  perror("mpz_init_set_str");
	  exit(1);
     }

     if(-1 == mpz_init_set_str(op2, key2, 16))
     {
	  perror("mpz_init_set_str");
	  exit(1);	  
     }
     // PRN("before exit\n");
     return mpz_cmp(op1, op2);
}

void key_set(char* key1, const char* key2)
{
     //PRN("enter\n");
     assert(NULL != key1);
     assert(NULL != key2);

     strcpy(key1, key2);
     //PRN("exit\n");
}

void key_k_start(char* key_k, const char* key, unsigned int k)
{
     //PRN("enter\n");
     assert(NULL != key_k);
     assert(NULL != key);

     mpz_t rop,op1, op2, op3;
     if(-1 == mpz_init_set_str(op1, key, 16))
     {
	  perror("mpz_set_str");
	  exit(1);
     }

     mpz_init(op2);
     mpz_ui_pow_ui(op2, 2, k);

     mpz_init(rop);
     mpz_add( rop, op1, op2);

     mpz_set(op1, rop);

     mpz_init(op3);
     mpz_ui_pow_ui(op3, 2, KEY_LEN * 8);

     mpz_mod(rop, op1, op3);
     //mpz_out_str(stdout, 16, rop);
     mpz_get_str(key_k, 16, rop);

     //PRN("exit\n");
}

void key_k_dec(char* key_k, const char* key, unsigned int k)
{
     //PRN("enter\n");
     assert(NULL != key_k);
     assert(NULL != key);

     mpz_t rop,op1, op2, op3;
     if(-1 == mpz_init_set_str(op1, key, 16))
     {
	  perror("mpz_set_str");
	  exit(1);
     }

     mpz_init(op2);
     mpz_ui_pow_ui(op2, 2, k);

     if(mpz_cmp(op1, op2) > 0)
     {
	  mpz_init(rop);
	  mpz_sub( rop, op1, op2);
	  mpz_get_str(key_k, 16, rop);
     }
     else
     {
	  mpz_init(op3);
	  mpz_ui_pow_ui(op3, 2, KEY_LEN * 8);
	  mpz_sub(rop, op3, op2);
	  mpz_set(op3, rop);
	  mpz_add(rop, op1, op3);
	  mpz_get_str(key_k, 16, rop);
     }
     //PRN("exit\n");
}

int isEmpty(Queue *q)
{
     if(q->front == q->rear)
	  return TRUE;
     return FALSE;
}

int isFull(Queue *q)
{
     if(q->front == (q->rear + 1) % QUEUE_SIZE )
	  return TRUE;
     return FALSE;
}

void enQueue(Queue *q, simple_rec_ptr request_data_ptr)
{
     if(TRUE == isFull(q))
     {
	  PRN(("Queue is full\n"));
	  exit(1);
     }

     q->request_data[q->rear].index = request_data_ptr->index;
     q->request_data[q->rear].request_response_type = request_data_ptr->request_response_type;
     q->request_data[q->rear].function_type = request_data_ptr->function_type;  
     q->request_data[q->rear].thread_id = request_data_ptr->thread_id;  
     if(request_data_ptr->key)	    
     {
	  assert(strlen(request_data_ptr->key) <= KEY_HEX_LEN);
	  strcpy(q->request_data[q->rear].key, request_data_ptr->key);
     }
     if(request_data_ptr->address)
     {
	  assert(strlen(request_data_ptr->address) <= ADDRESS_LEN);
	  strcpy(q->request_data[q->rear].address, request_data_ptr->address);
     }
     if(request_data_ptr->name)	    
     {
	  assert (strlen(request_data_ptr->name) <= NAME_MAX_LEN);
	  strcpy(q->request_data[q->rear].name, request_data_ptr->name);
     }
     if(request_data_ptr->value)
     {
	  assert(strlen(request_data_ptr->value) <= VALUE_MAX_LEN);
	  strcpy(q->request_data[q->rear].value, request_data_ptr->value);
     }

     q->rear = (q->rear + 1) % QUEUE_SIZE;
}

void deQueue(Queue * q, simple_rec_ptr request_data_ptr)
{
     if(TRUE == isEmpty(q))
     {
	  PRN(("Queue is Empty\n"));
	  exit(1);
     }

     request_data_ptr->index = q->request_data[q->front].index;
     request_data_ptr->request_response_type = q->request_data[q->front].request_response_type;
     request_data_ptr->function_type = q->request_data[q->front].function_type;  
     request_data_ptr->thread_id = q->request_data[q->front].thread_id;  

     if(q->request_data[q->front].key)	    
     {
	  strcpy(request_data_ptr->key, q->request_data[q->front].key);
     }
     if(q->request_data[q->front].address)
     {
	  strcpy(request_data_ptr->address, q->request_data[q->front].address);
     }
     if(q->request_data[q->front].name)
     {
	  strcpy(request_data_ptr->name, q->request_data[q->front].name);
     }
     if(q->request_data[q->front].value)
     {
	  strcpy(request_data_ptr->value, q->request_data[q->front].value);
     }

     /*init dequeued buffer*/
     memset(q->request_data[q->front].key, 0, KEY_HEX_LEN);
     memset(q->request_data[q->front].address, 0, ADDRESS_LEN);
     memset(q->request_data[q->front].name, 0, NAME_MAX_LEN);
     memset(q->request_data[q->front].value, 0, VALUE_MAX_LEN);

     q->front = (q->front + 1) % QUEUE_SIZE;
}

void initQueue(Queue *q)
{
     q->front = 0;
     q->rear = 0;
     memset(q->request_data, 0, sizeof(simple_rec) * QUEUE_SIZE);

     int i;
     for(i = 0; i < QUEUE_SIZE; i++)
     {
	  q->request_data[i].key = (char*)malloc(sizeof(char) * KEY_HEX_LEN);
	  assert(NULL != q->request_data[i].key);
	  q->request_data[i].address = (char*)malloc(sizeof(char) * ADDRESS_LEN);
	  assert(NULL != q->request_data[i].address);    
	  q->request_data[i].name = (char*)malloc(sizeof(char) * NAME_MAX_LEN);
	  assert(NULL != q->request_data[i].name);
	  q->request_data[i].value = (char*)malloc(sizeof(char) * VALUE_MAX_LEN);
	  assert(NULL != q->request_data[i].value);    	  
     }
}

void log_finger_table()
{
     PRN("\n\n\nFinger Table\n");
     PRN("Index\tStart Key\t\t\t\t\t\tSuccessor Key\t\t\t\t\t\t\t Successor Address\n");
     int i;
     for(i = 0; i < NUM_FINGER_TABLE_ELEMENT; i++)
     {
	  PRN("%d %s\t%s\t%s\n", i, ft.finger[i].start, ft.finger[i].successor_key, ft.finger[i].successor_address);
     }
     FFLUSH(Log);
}

void Send(simple_rec_ptr data, char* addr)
{
     PRN("enter\n");

     //PRN("wait for lock\n");
     //pthread_mutex_lock (&m_send_func);
     //PRN("mutex locked\n");

     usleep(1);
     char string_list[2048];
     attr_list contact_list;
     EVstone remote_stone;
     
     PRN("I send to [%s]\n", addr);
     PRN("I send int=[%d]\n", data->index);
     PRN("I send request_response_type=[%d]\n", data->request_response_type);
     PRN("I send func=[%s]\n", data->function_name);
     if(data->key) PRN("I send key=[%s]\n", data->key);
     if(data->address) PRN("I send addr=[%s]\n", data->address);
     PRN("I send thread_id=[%lu]\n", data->thread_id);

     if (sscanf(addr, "%d:%s", &remote_stone, &string_list[0]) != 2) {
	  PRN("Bad arguments \"%s\"\n", addr);
	  exit(0);
     }

     EVstone stone = EValloc_stone(cm);

     contact_list = attr_list_from_string(string_list);
     EVassoc_bridge_action(cm, stone, contact_list, remote_stone);
     EVsource source = EVcreate_submit_handle(cm, stone, simple_format_list);

     EVsubmit(source, data, NULL);
     //pthread_mutex_unlock (&m_send_func);
     //PRN("mutex unlocked\n");
     PRN("exit\n");
     FFLUSH(Log);
}

void find_successor(char* key, char* successor_key, char* successor_address)
{
     PRN("enter\n");
     assert(NULL != key);
     assert(NULL != successor_key);
     assert(NULL != successor_address);

     char predecessor_key[KEY_HEX_LEN]="", predecessor_address[ADDRESS_LEN]="";

     find_predecessor(key, predecessor_key, predecessor_address);

     if(0 == strcmp(predecessor_address, ft.node_address)) 
     {
	  PRN("local get_successor\n");
	  strcpy(successor_key, ft.finger[0].successor_key);
	  strcpy(successor_address, ft.finger[0].successor_address);	  
     }
     else
     {
	  /*remotely invoke get_successor*/
	  PRN("remote get_successor\n");		  
	  simple_rec request_data;
	  memset(&request_data, 0, sizeof(request_data));
	  request_data.function_name = "get_successor";
	  request_data.function_type = Get_Successor;
	  request_data.address = ft.node_address;
	  request_data.request_response_type = Request;
	  request_data.thread_id = pthread_self();
	  //wait = 1;
	  Send(&request_data, predecessor_address);
	  
	  PRN("waiting for response\n");
	  pthread_mutex_lock (&m_response);
	  pthread_cond_wait(&c_serve_response, &m_response);
	  PRN("got response\n");

	  if(response_data.thread_id != pthread_self())
	  {
	       PRN("response_data.thread_id [%ld]!= pthread_self() [%ld] ...waiting for response\n", response_data.thread_id, pthread_self());
	       pthread_cond_wait(&c_serve_response, &m_response);
	  }
	    
	  //while(1 == wait) ;

	  PRN("response key=[%s]\n", response_data.key);
	  PRN("response addr=[%s]\n", response_data.address);
	  strcpy(successor_key, response_data.key);
	  strcpy(successor_address, response_data.address);	  
	  pthread_mutex_unlock (&m_response);
     }
     PRN("exit\n");
}

int evaluate_condition(char* key, char* node_key, char* node_address)
{
     PRN("enter\n");
     assert(NULL != key);
     assert(NULL != node_key);
     assert(NULL != node_address);

     char node_successor_key[KEY_HEX_LEN] = "";
	  
     if(0 != strcmp(ft.node_address, node_address))
     {
	  /*remotely invoke get_successor*/
	  simple_rec request_data;
	  memset(&request_data, 0, sizeof(request_data));
	  request_data.function_name = "get_successor";
	  request_data.function_type = Get_Successor;
	  request_data.address = ft.node_address;
	  request_data.request_response_type = Request;
	  request_data.thread_id = pthread_self();
	  //wait = 1;
	  Send(&request_data, node_address);

	  PRN("waiting for response\n");
	  pthread_mutex_lock (&m_response );
	  pthread_cond_wait(&c_serve_response, &m_response);
	  PRN("got response\n");

	  if(response_data.thread_id != pthread_self())
	  {
	       PRN("response_data.thread_id != pthread_self() ...waiting for response\n");
	       pthread_cond_wait(&c_serve_response, &m_response);
	       PRN("got response\n");
	  }

	  //while(1 == wait) ;

	  PRN("response key=[%s]\n", response_data.key);
	  PRN("response addr=[%s]\n", response_data.address);
	  strcpy(node_successor_key, response_data.key);
	  pthread_mutex_unlock(&m_response);
     }
     else
     {
	  strcpy(node_successor_key, ft.finger[0].successor_key);	       
     }

     int condition = 0;
     
     if(key_compare(node_key, node_successor_key) < 0)
     {
	  condition = (key_compare(key, node_key) <= 0) || (key_compare(key, node_successor_key) > 0);
     }
     else
     {
	  condition = (key_compare(key, node_key) <= 0) && (key_compare(key, node_successor_key) > 0);
     }
     PRN("cond=[%d] key=[%s] node=[%s] succ=[%s]", condition, key, node_key, node_successor_key);
     PRN("exit\n");
     return condition;
}

void find_predecessor(char* key, char* predecessor_key, char* predecessor_address)
{
     assert(NULL != key);
     assert(NULL != predecessor_key);
     assert(NULL != predecessor_address);

     PRN("enter key=[%s]\n", key);

     char node_key[KEY_HEX_LEN] = "", node_address[ADDRESS_LEN] = "";
     simple_rec request_data;
     memset(&request_data, 0, sizeof(request_data));

     strcpy(node_key, ft.node_key);
     strcpy(node_address, ft.node_address);
     
     while(1 == evaluate_condition(key, node_key, node_address))
     {
	  if(0 != strcmp(ft.node_address, node_address))
	  {
	       /*remotely invoke closest_preceding_finger*/
	       memset(&request_data, 0, sizeof(request_data));
	       request_data.function_name = "closest_preceding_finger";
	       request_data.function_type = Closest_Preceding_Finger;
	       request_data.key = key;
	       request_data.address = ft.node_address;
	       request_data.request_response_type = Request;
	       request_data.thread_id = pthread_self();
	       //wait = 1;
	       Send(&request_data, node_address);
	       
	       PRN("waiting for response\n");
	       pthread_mutex_lock (&m_response);
	       pthread_cond_wait(&c_serve_response, &m_response);
	       PRN("got response\n");

	       if(response_data.thread_id != pthread_self())
	       {
		    PRN("response_data.thread_id != pthread_self() ...waiting for response\n");
		    pthread_cond_wait(&c_serve_response, &m_response);
		    PRN("got response\n");
	       }

	       //while( 1 == wait) ;
	       
	       PRN("response key=[%s]\n", response_data.key);
	       PRN("response addr=[%s]\n", response_data.address);
	       strcpy(node_key, response_data.key);
	       strcpy(node_address, response_data.address);
	       pthread_mutex_unlock(&m_response);
	  }
	  else
	  {
	       closest_preceding_finger(key, node_key, node_address);
	  }
     }

     strcpy(predecessor_key, node_key);
     strcpy(predecessor_address, node_address);
     PRN("exit\n");
}

void closest_preceding_finger(char* key, char* next_node_key, char* next_node_address)
{
     PRN("enter\n");
     assert(NULL != key);
     assert(NULL != next_node_key);
     assert(NULL != next_node_address);

     int i;
     int condition = 0;

     for(i = NUM_FINGER_TABLE_ELEMENT - 1; i >= 0; i--)
     {
	  condition = 0;
	  if(NULL != ft.finger[i].successor_key)
	  {
	       if(key_compare(ft.node_key, key) < 0)
	       {
		    condition = (key_compare(ft.finger[i].successor_key, ft.node_key) > 0) && (key_compare(ft.finger[i].successor_key, key) < 0);
	       }
	       else
	       {
		    condition = (key_compare(ft.finger[i].successor_key, ft.node_key) > 0) || (key_compare(ft.finger[i].successor_key, key) < 0);
	       }

	       if(condition)
	       {
		    strcpy(next_node_key, ft.finger[i].successor_key);
		    strcpy(next_node_address, ft.finger[i].successor_address);
		    PRN("exit\n");
		    return;
	       }
	  }
     }
     strcpy(next_node_key, ft.node_key);
     strcpy(next_node_address, ft.node_address);
     PRN("exit\n");
}

void join(char* node_address, char* existing_node_address)
{
     PRN("enter\n");
     assert(NULL != node_address);
     int k;
     
     pthread_mutex_lock(&m_finger_table);
     key_compute(node_address, ft.node_key);
     strcpy(ft.node_address, node_address);

     if(NULL == existing_node_address)
     {
	  strcpy(ft.predecessor_key, ft.node_key);
	  strcpy(ft.predecessor_address, ft.node_address);
	  for(k = 0; k < NUM_FINGER_TABLE_ELEMENT; k++)
	  {
	       key_k_start(ft.finger[k].start, ft.node_key, k);
	       strcpy(ft.finger[k].successor_key, ft.node_key);
	       strcpy(ft.finger[k].successor_address, ft.node_address);		    
	  }
	  pthread_mutex_unlock(&m_finger_table);
     }
     else
     {
	  pthread_mutex_unlock(&m_finger_table);
	  init_finger_table(node_address, existing_node_address);
	  update_others();	  
     }
     PRN("exit\n");
}

void init_finger_table(char* node_address, char* existing_node_address)
{
     PRN("enter\n");
     assert(NULL != node_address);
     assert(NULL != existing_node_address);
     
     pthread_mutex_lock(&m_finger_table);

     key_compute(node_address, ft.node_key);
     strcpy(ft.node_address, node_address);
     key_k_start(ft.finger[0].start, ft.node_key, 0);


     /* remotely invoke find_successor */
     simple_rec request_data;
     memset(&request_data, 0, sizeof(request_data));
     request_data.function_name = "find_successor";
     request_data.function_type = Find_Successor;
     request_data.key = ft.finger[0].start;
     request_data.address = ft.node_address;
     request_data.request_response_type = Request;
     request_data.thread_id = pthread_self();
     //wait = 1;
     Send(&request_data, existing_node_address);

     PRN("waiting for response\n");
     pthread_mutex_lock (&m_response);
     pthread_cond_wait(&c_serve_response, &m_response);
     PRN("got response\n");

     if(response_data.thread_id != pthread_self())
     {
	  PRN("response_data.thread_id != pthread_self() ...waiting for response\n");
	  pthread_cond_wait(&c_serve_response, &m_response);
	  PRN("got response\n");
     }

     //while(1 == wait) ;

     PRN("response key=[%s]\n", response_data.key);
     PRN("response addr=[%s]\n", response_data.address);
     strcpy(ft.finger[0].successor_key, response_data.key);
     strcpy(ft.finger[0].successor_address, response_data.address);
     pthread_mutex_unlock(&m_response);
     
     /*remotely invoke get_predecessor*/
     memset(&request_data, 0, sizeof(request_data));
     request_data.function_name = "get_predecessor";
     request_data.function_type = Get_Predecessor;
     request_data.address = ft.node_address;
     request_data.request_response_type = Request;
     request_data.thread_id = pthread_self();
     //wait = 1;
     Send(&request_data, ft.finger[0].successor_address);

     PRN("waiting for response\n");
     pthread_mutex_lock (&m_response);
     pthread_cond_wait(&c_serve_response, &m_response);
     PRN("got response\n");

     if(response_data.thread_id != pthread_self())
     {
	  PRN("response_data.thread_id != pthread_self() ...waiting for response\n");
	  pthread_cond_wait(&c_serve_response, &m_response);
	  PRN("got response\n");
     }

     //while(1 == wait) ;

     PRN("response key=[%s]\n", response_data.key);
     PRN("response addr=[%s]\n", response_data.address);
     strcpy(ft.predecessor_key, response_data.key);
     strcpy(ft.predecessor_address, response_data.address);     
     pthread_mutex_unlock(&m_response);

     /*remotely invoke set_predecessor*/
     memset(&request_data, 0, sizeof(request_data));
     request_data.function_name = "set_predecessor";
     request_data.function_type = Set_Predecessor;
     request_data.address = ft.node_address;
     request_data.key = ft.node_key;
     request_data.request_response_type = Request;
     Send(&request_data, ft.finger[0].successor_address);

     int k;
     int condition;

     for(k = 0; k < NUM_FINGER_TABLE_ELEMENT - 1; k++)
     {
	  key_k_start(ft.finger[k + 1].start, ft.node_key, k + 1);

	  condition = 0;
	  
	  if(key_compare(ft.node_key, ft.finger[k].successor_key) < 0)
	  {
	       condition = (key_compare(ft.finger[k + 1].start, ft.node_key) >= 0)  && (key_compare(ft.finger[k+1].start, ft.finger[k].successor_key) < 0);
	  }
	  else
	  {
	       condition = (key_compare(ft.finger[k + 1].start, ft.node_key) >= 0)  || (key_compare(ft.finger[k+1].start, ft.finger[k].successor_key) < 0);
	  }

	  if(condition)
	  {
	       strcpy(ft.finger[k+1].successor_key, ft.finger[k].successor_key); 
	       strcpy(ft.finger[k+1].successor_address, ft.finger[k].successor_address); 
	  }
	  else
	  {
	       /* remotely invoke find_successor */
	       simple_rec request_data;
	       memset(&request_data, 0, sizeof(request_data));
	       request_data.function_name = "find_successor";
	       request_data.function_type = Find_Successor;
	       request_data.key = ft.finger[k + 1].start;
	       request_data.address = ft.node_address;
	       request_data.request_response_type = Request;
	       request_data.thread_id = pthread_self();
	       //wait = 1;
	       Send(&request_data, existing_node_address);

	       PRN("waiting for response\n");
	       pthread_mutex_lock (&m_response);
	       pthread_cond_wait(&c_serve_response, &m_response);
	       PRN("got response\n");

	       if(response_data.thread_id != pthread_self())
	       {
		    PRN("response_data.thread_id != pthread_self() ...waiting for response\n");
		    pthread_cond_wait(&c_serve_response, &m_response);
		    PRN("got response\n");
	       }

	       //while(1 == wait) ;

	       PRN("response key=[%s]\n", response_data.key);
	       PRN("response addr=[%s]\n", response_data.address);
	       strcpy(ft.finger[k + 1].successor_key, response_data.key);
	       strcpy(ft.finger[k + 1].successor_address, response_data.address);
	       pthread_mutex_unlock(&m_response);
	  }
     }

     pthread_mutex_unlock(&m_finger_table);
     PRN("exit\n");
}

void update_others()
{
     PRN("enter\n");
     
     char predecessor_key[KEY_HEX_LEN]="", predecessor_address[ADDRESS_LEN]="", tmp[KEY_HEX_LEN]="";
     int k;

     for(k = 0; k < NUM_FINGER_TABLE_ELEMENT - 1; k++)
     {
	  key_k_dec(tmp, ft.node_key, k);
	  find_predecessor(tmp, predecessor_key, predecessor_address);
	  PRN("predecessor addr=[%s]\n", predecessor_address);
	  PRN("current addr=[%s]\n", ft.node_address);
	  if(0 != strcmp(ft.node_address, predecessor_address))
	  {
	       /* remotely invoke update_finger_table */
	       simple_rec request_data;
	       memset(&request_data, 0, sizeof(request_data));
	       request_data.function_name = "update_finger_table";
	       request_data.function_type = Update_Finger_Table;
	       request_data.index = k;
	       request_data.key = ft.node_key;
	       request_data.address = ft.node_address;
	       request_data.request_response_type = Request;
	       Send(&request_data, predecessor_address);
	  }
     }
     PRN("exit\n");
}

void update_finger_table(char* new_node_key, char* new_node_address, int i)
{
     PRN("enter\n");
     assert(NULL != new_node_key);
     assert(NULL != new_node_address);

     int condition = 0;
	  
     if(key_compare(ft.node_key, ft.finger[i].successor_key) < 0)
     {
	  condition = (key_compare(new_node_key, ft.node_key) >= 0) && (key_compare(new_node_key, ft.finger[i].successor_key) < 0);
     }
     else
     {
	  condition = (key_compare(new_node_key, ft.node_key) >= 0) || (key_compare(new_node_key, ft.finger[i].successor_key) < 0);
     }

     if(condition)
     {
	  PRN("condition is true\n");
	  pthread_mutex_lock(&m_finger_table);
	  strcpy(ft.finger[i].successor_key, new_node_key);
	  strcpy(ft.finger[i].successor_address, new_node_address);
	  pthread_mutex_unlock(&m_finger_table);

	  if(0 != strcmp(new_node_address, ft.predecessor_address))
	  {
	       /* remotely invoke update_finger_table */
	       simple_rec request_data;
	       memset(&request_data, 0, sizeof(request_data));
	       request_data.function_name = "update_finger_table";
	       request_data.function_type = Update_Finger_Table;
	       request_data.index = i;
	       request_data.key = new_node_key;
	       request_data.address = new_node_address;
	       request_data.request_response_type = Request;
	       Send(&request_data, ft.predecessor_address);	
	  }
     }
     PRN("exit\n");	  
}

void get_successor(char* successor_key, char* successor_address)
{
     PRN("enter\n");
     assert(NULL != successor_key);
     assert(NULL != successor_address);
     
     strcpy(successor_key, ft.finger[0].successor_key);
     strcpy(successor_address, ft.finger[0].successor_address);
     PRN("exit\n");
}

void get_predecessor(char* predecessor_key, char* predecessor_address)
{
     PRN("enter\n");
     assert(NULL != predecessor_key);
     assert(NULL != predecessor_address);
     
     strcpy(predecessor_key, ft.predecessor_key);
     strcpy(predecessor_address, ft.predecessor_address);
     PRN("exit\n");
}

void set_predecessor(char* node_key, char* node_address)
{
     PRN("enter\n");
     assert(NULL != node_key);
     assert(NULL != node_address);

     pthread_mutex_lock(&m_finger_table);
     strcpy(ft.predecessor_key, node_key);
     strcpy(ft.predecessor_address, node_address);
     pthread_mutex_unlock(&m_finger_table);

     PRN("exit\n");
}

void put_data(hash_table* table, char* key, char* name, char* value)
{
     assert(NULL != table);
     assert(NULL != name);
     assert(NULL != value);
     assert(NULL != key);

     PRN("enter name=[%s] value=[%s] index=[%d]\n", name, value, list.index);
     //fprintf(stdout, "enter name=[%s] value=[%s] index=[%d]\n", name, value, list.index);
     
     // strncpy(list.record[list.index].name, name, NAME_MAX_LEN);
     //strncpy(list.record[list.index].value, value, VALUE_MAX_LEN);  
     //list.index++;
     update_add_hash(table, key, name, value);
     PRN("exit\n");
}

void get_data(hash_table* table, char* key, char* name, char* value)
{
     assert(NULL != table);
     assert(NULL != name);
     assert(NULL != value);

     PRN("enter name=[%s]\n", name);
     //fprintf(stdout, "enter name=[%s]\n", name);
     hash_lookup(table, key, name, value);
     PRN("value=[%s]\n", value);
#if 0
     int i;
     
     for(i = 0; i < list.index; i++)
     {
	  if(0 == strcmp(list.record[i].name, name))
	  {
	       strcpy(value, list.record[i].value);  
	       PRN("value found = [%s]\n", value);
	       fprintf(stdout, "value found = [%s]\n", value);
	       PRN("exit\n");
	       return;
	  }	     
     }
     fprintf(stdout, "value not found\n");
     PRN("exit\n");
#endif
}


void check_update_predecessor(char *request_node_key, char *request_node_address)
{
     PRN("enter\n");
     assert(NULL != request_node_key);
     assert(NULL != request_node_address);
     int condition = 0;

     if(NULL != ft.predecessor_key)
     {
	  if(key_compare(ft.predecessor_key, ft.node_key) < 0)
	  {
	       condition = (key_compare(request_node_key, ft.predecessor_key) > 0) && (key_compare(request_node_key, ft.node_key) < 0);
	  }
	  else
	  {
	       condition = (key_compare(request_node_key, ft.predecessor_key) > 0) || (key_compare(request_node_key, ft.node_key) < 0);
	  }
     }
     
     if((NULL == ft.predecessor_key) || condition)
     {
	  pthread_mutex_lock(&m_finger_table);		  
	  strcpy(ft.predecessor_key, request_node_key);
	  strcpy(ft.predecessor_address, request_node_address);
	  pthread_mutex_unlock(&m_finger_table);
     }

     PRN("exit\n");
}

void store_data(char *name, unsigned long value)
{
     char value_buff[NAME_MAX_LEN]="";
     char key[KEY_HEX_LEN]="";
     char successor_key[KEY_HEX_LEN]="";
     char successor_address[ADDRESS_LEN]="";
     simple_rec request_data;
     memset(&request_data, 0, sizeof(request_data));

     sprintf(value_buff, "%ld", value);
     key_compute(name, key);
     find_successor(key, successor_key, successor_address);
  
     PRN("name=[%s] key=[%s] successor_key=[%s] successor_address=[%s]\n", name, key, successor_key, successor_address);
     if(0 == strcmp(ft.node_address, successor_address))
     {
	  put_data(table, ft.node_address, name, value_buff);
     }
     else
     {
	  /* remotely invoke put_data */
	  request_data.function_name = "put_data";
	  request_data.function_type = Put_Data;
	  request_data.key = ft.node_address;
	  request_data.name = name;                   
	  request_data.value = value_buff;                
	  request_data.address = ft.node_address;
	  request_data.request_response_type = Request;
	  Send(&request_data, successor_address);
     }
}

void store_string_data(char *name, char* value)
{
     char key[KEY_HEX_LEN]="";
     char successor_key[KEY_HEX_LEN]="";
     char successor_address[ADDRESS_LEN]="";
     simple_rec request_data;
     memset(&request_data, 0, sizeof(request_data));

     key_compute(name, key);
     find_successor(key, successor_key, successor_address);
  
     PRN("name=[%s] key=[%s] successor_key=[%s] successor_address=[%s]\n", name, key, successor_key, successor_address);
     if(0 == strcmp(ft.node_address, successor_address))
     {
	  put_data(table, ft.node_address, name, value);
     }
     else
     {
	  /* remotely invoke put_data */
	  request_data.function_name = "put_data";
	  request_data.function_type = Put_Data;
	  request_data.key = ft.node_address;
	  request_data.name = name;                   
	  request_data.value = value;                
	  request_data.address = ft.node_address;
	  request_data.request_response_type = Request;
	  Send(&request_data, successor_address);
     }
}
