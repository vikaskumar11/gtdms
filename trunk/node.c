#include "lib.h"

FingerTable ft;                                            //Figure Table used for routig request to appropriate node
hash_table* table;
List list;                                                  //Array of records stored at this node 
int wait;                                                   //Flag used to do synchronous/blocking send 
simple_rec response_data;                                   //Response data recieved when send returns
CManager cm;                                                //Connection Manager for evpath
Queue q_request;                                            //Queue to maintain incoming request for serve_request to pick
pthread_mutex_t m_request = PTHREAD_MUTEX_INITIALIZER;       //Mutex for protecting request Queue q
pthread_cond_t c_request_handler = PTHREAD_COND_INITIALIZER; //Condition variable on which request handler waits if queue is full
pthread_cond_t c_serve_request = PTHREAD_COND_INITIALIZER;   //Condition variable on which serve_request waits if queue is empty
pthread_mutex_t m_response = PTHREAD_MUTEX_INITIALIZER;      //Mutex for protecting response Queue q
pthread_cond_t c_serve_response = PTHREAD_COND_INITIALIZER;  //Condition variable functions to wait for response 
pthread_mutex_t m_hash_table = PTHREAD_MUTEX_INITIALIZER;    //synchronize for hash table access
pthread_mutex_t m_finger_table = PTHREAD_MUTEX_INITIALIZER;  //synchronize for finger table access
FILE *Log;                                                  //Log all activity to disk file
pthread_key_t log_key;                                      //key for thread specific log handle

void* get_store_data(void* v)
{
     OPEN_THREAD_LOG_FILE();
     PRN("enter\n");
     glibtop_init();
     while(1)
     {
	  /*CPU realted stats*/
	  glibtop_cpu cpu;
	  glibtop_get_cpu (&cpu);
	  store_data("cpu total", cpu.total);
	  store_data("cpu user", cpu.user);
	  store_data("cpu nice", cpu.nice);
	  store_data("cpu sys", cpu.sys);
	  store_data("cpu idle", cpu.idle);
	  store_data("cpu iowait", cpu.iowait);
	  store_data("cpu irq", cpu.irq);
	  store_data("cpu softirq", cpu.softirq);
	  store_data("cpu frequency", cpu.frequency);

	  /*Memory realted stats*/
	  glibtop_mem memory;
	  glibtop_get_mem(&memory);  
	  store_data("memory total in MB", memory.total/(1024*1024));
	  store_data("memory used in MB", memory.used/(1024*1024));
	  store_data("memory free in MB", memory.free/(1024*1024));
	  store_data("memory shared in MB", memory.shared/(1024*1024));
	  store_data("memory buffer in MB", memory.buffer/(1024*1024));
	  store_data("memory cached in MB", memory.cached/(1024*1024));
	  store_data("memory user in MB", memory.user/(1024*1024));
	  store_data("memory locked in MB", memory.locked/(1024*1024));

	  glibtop_proclist proclist;
	  int which,arg;
	  unsigned *ptr, *ptr1;
	  int i;
	  ptr1 = glibtop_get_proclist(&proclist, 0, 0);
	  //ptr = ptr1;
	  // printf("Process List Flags %x\n Number %ld\n",(unsigned long)proclist.flags,(unsigned long)proclist.number);
	  g_free(ptr1);

	  /*Swap related stats*/
	  glibtop_swap swap;
	  glibtop_get_swap(&swap);
	  store_data("Swap total in MB", swap.total/(1024*1024));
	  store_data("Swap used in MB", swap.used/(1024*1024));
	  store_data("Swap free in MB", swap.free/(1024*1024));
	  store_data("Swap pagein in MB", swap.pagein/(1024*1024));
	  store_data("Swap pageout", swap.pageout/(1024*1024));

	  /*Stats related to uptime*/
	  glibtop_uptime uptime;
	  glibtop_get_uptime(&uptime);
	  store_data("Uptime in min", uptime.uptime);
	  store_data("Idletime in min", uptime.idletime);
	  store_data("Boottime in min", uptime.boot_time);

	  /*Stats related to loadavg*/
	  glibtop_loadavg loadavg;
	  glibtop_get_loadavg(&loadavg);
	  store_data("load avg over 1 min", loadavg.loadavg[0]);
	  store_data("load avg over 5 min", loadavg.loadavg[1]);
	  store_data("load avg over 15 min", loadavg.loadavg[2]);
	  store_data("number of currently running task", loadavg.nr_running);
	  store_data("total number of task", loadavg.nr_tasks);

	  /*Stats related to netload*/
	  glibtop_netload netload;
	  glibtop_get_netload(&netload, "eth0");
	  store_data("if_flags", netload.if_flags);
	  store_data("mtu", netload.mtu);
	  store_data("subnet", netload.subnet);
	  store_data("address", netload.address);
	  store_data("packets in", netload.packets_in);
	  store_data("packets out", netload.packets_out);
	  store_data("packets total", netload.packets_total);
	  store_data("bytes in", netload.bytes_in);
	  store_data("bytes out", netload.bytes_out);
	  store_data("bytes total", netload.bytes_total);
	  store_data("errors in", netload.errors_in);
	  store_data("errors out", netload.errors_out);
	  store_data("errors total", netload.errors_total);
	  store_data("total number of collision", netload.collisions);

	  /*Stats related to mount list*/
	  glibtop_mountlist mountlist;
	  glibtop_mountentry *ptr_m;
	  int all_fs = 1;
	  ptr_m = glibtop_get_mountlist(&mountlist, all_fs);
	  for(i=0; i<mountlist.number; i++)
	  {
	       store_string_data("mount devname", ptr_m[i].devname);
	       store_string_data("mount dir", ptr_m[i].mountdir);
	       store_string_data("mount type", ptr_m[i].type);
	  }
	  g_free(ptr_m);

	  sleep(60);
     }
     return 0;
}

void* delete_stale_data (void *a)
{
     OPEN_THREAD_LOG_FILE();
     PRN("enter\n");
     
     int hashno = 0;
     hash_bucket *bp, *pbp = (hash_bucket *)0;
     char key[KEY_HEX_LEN]="";
     char successor_key[KEY_HEX_LEN]="";
     char successor_address[ADDRESS_LEN]="";
     int condition = 0;

     while(1)
     {

	  /*need to periodically do clean up*/
	  sleep(120);

	  /* Go through the list looking for an entry that matches;
	     if we find it, delete it. */

	  pthread_mutex_trylock(&m_hash_table);	  

	  PRN("locked\n");
	  for( hashno = 0; hashno < table -> hash_count; hashno++)
	  {
	       //printf("inside for hashno=[%d]\n", hashno);
	       bp = table->buckets[hashno];
	       pbp = 0;
	       while(bp)
	       {
		    key_compute(bp -> name, key);		 		  
		    condition = 0;
		    if(key_compare(ft.predecessor_key, ft.node_key) < 0)
		    {
			 condition = (key_compare(key, ft.predecessor_key) > 0) && (key_compare(key, ft.node_key) <= 0);
		    }
		    else
		    {
			 condition = (key_compare(key, ft.predecessor_key) > 0) || (key_compare(key, ft.node_key) <= 0);
		    }
    
		    //find_successor(key, successor_key, successor_address);
		    //printf("inside while msg=[%s] suc_address[%s]\n", bp->name, successor_address);
		    //PRN("name=[%s] key=[%s] successor_key=[%s] successor_address=[%s]\n", bp->name, key, successor_key, successor_address);
		    
		    if(0 == condition)
		    {
			 if(pbp)
			 {
			      pbp->next = bp->next;
			      free(bp);
			      bp = pbp;
			 }
			 else
			 {
			      table->buckets[hashno] = bp->next;
			      free(bp);
			      bp = table->buckets[hashno];
			      continue;
			 }			      
		    }
		    pbp = bp;
		    bp = bp->next;
	       }
	  }
	  pthread_mutex_unlock(&m_hash_table);
	  PRN("unlocked\n");
     }
     PRN("exit\n");
}

void* serve_request(void *vevent)
{
     OPEN_THREAD_LOG_FILE();
     PRN("enter\n");
     simple_rec request_data;
     char request_key[KEY_HEX_LEN] = "";
     char request_address[ADDRESS_LEN] = "";
     char name_buff[NAME_MAX_LEN] = "";
     char value_buff[VALUE_MAX_LEN] = "";
     
     memset(&request_data, 0, sizeof(request_data));
     request_data.key = request_key;
     request_data.address = request_address;
     request_data.name = name_buff;
     request_data.value = value_buff;

     simple_rec response_data;
     char response_key[KEY_HEX_LEN] = "";
     char response_address[ADDRESS_LEN] = "";
     char response_value[VALUE_MAX_LEN] = "";
     memset(&response_data, 0, sizeof(response_data));
     response_data.key = response_key;
     response_data.address = response_address;
     response_data.request_response_type = Response;
     response_data.value = value_buff;

     while(1)
     {
	  /*init all buffers on stack*/
	  memset(request_data.key, 0, KEY_HEX_LEN);
	  memset(request_data.address, 0, ADDRESS_LEN);
	  memset(request_data.name, 0, NAME_MAX_LEN);
	  memset(request_data.value, 0, VALUE_MAX_LEN);
	  memset(response_data.key, 0, KEY_HEX_LEN);
	  memset(response_data.address, 0, ADDRESS_LEN);
	  
	  pthread_mutex_lock (&m_request);
	  while(TRUE == isEmpty(&q_request))
	  {
	       PRN("waiting to deque request\n");
	       pthread_cond_wait(&c_serve_request, &m_request);
	  }
	  deQueue(&q_request, &request_data);
	  PRN("Request dequed\n");
	  pthread_cond_signal(&c_request_handler);
	  pthread_mutex_unlock(&m_request);
	  
	  PRN("serving [%ld]\n", pthread_self());
	  PRN("I got int=[%d]\n", request_data.index);
	  PRN("I got request_response_type=[%d]\n", request_data.request_response_type);
	  PRN("I got thread_id=[%d]\n", request_data.thread_id);
	  if(request_data.key) PRN("I got key=[%s]\n", request_data.key);
	  if(request_data.address) PRN("I got addr=[%s]\n", request_data.address);	 
	  response_data.thread_id = request_data.thread_id;
	  
	  switch (request_data.function_type)
	  {
	  case Find_Successor:
	       find_successor(request_data.key, response_data.key, response_data.address);
	       Send(&response_data, request_data.address);
	       break;	       
	  case Get_Successor:
	       get_successor(response_data.key, response_data.address);
	       Send(&response_data, request_data.address);
	       break;
	  case Get_Predecessor:
	       get_predecessor(response_data.key, response_data.address);	       
	       Send(&response_data, request_data.address);
	       break;
	  case Set_Predecessor:
	       set_predecessor(request_data.key, request_data.address);
	       break;
	  case Closest_Preceding_Finger:
	       closest_preceding_finger(request_data.key, response_data.key, response_data.address);
	       Send(&response_data, request_data.address);
	       break;
	  case Update_Finger_Table:
	       update_finger_table(request_data.key, request_data.address, request_data.index);
	       break;
	  case Log_Finger_Table:
	       log_finger_table();
	       break;
	  case Put_Data:
	       put_data(table, request_data.key, request_data.name, request_data.value);
	       break;
	  case Get_Data:
	       get_data(table, request_data.key, request_data.name, response_data.value);
	       Send(&response_data, request_data.address);
	       break;
	  case Check_Update_Predecessor:
	       check_update_predecessor(request_data.key, request_data.address);
	       break;
	  default:
	       PRN("None of cases matched\n");
	       exit(1);
	  }
	  PRN("served [%ld]\n", pthread_self());
	  FFLUSH(Log);
     }
     PRN("exit\n");
     FFLUSH(Log);
     return 0;
}

static int simple_handler(CManager cm, void *vevent, void *client_data, attr_list attrs)
{
     PRN("enter\n");
     simple_rec_ptr event = vevent;
     PRN("I got int=[%d]\n", event->index);
     PRN("I got request_response_type=[%d]\n", event->request_response_type);
     if(event->key) PRN("I got key=[%s]\n", event->key);
     if(event->address) PRN("I got addr=[%s]\n", event->address);	 
     
     if(Request == event->request_response_type)
     {
	  assert(NULL != event->function_name);
	  PRN("Request received\n");
	  PRN("I got func=[%s]\n", event->function_name);

	  pthread_mutex_lock (&m_request);
          while(TRUE == isFull(&q_request))
	  {
	       PRN("Waiting to enque request\n");
               pthread_cond_wait(&c_request_handler, &m_request);
	  }
          enQueue(&q_request, event);
	  PRN("Request enqued\n");
          pthread_cond_signal(&c_serve_request);
          pthread_mutex_unlock(&m_request);
     }
     else
     {
	  /*Response received*/
	  PRN("Response received\n");
	  pthread_mutex_lock (&m_response);
	  response_data.thread_id = event->thread_id;
	  response_data.index = event->index;
	  strcpy(response_data.key, event->key);
	  strcpy(response_data.address, event->address);
	  assert(strlen(event->value) < VALUE_MAX_LEN);
	  strcpy(response_data.value, event->value);
	  pthread_mutex_unlock (&m_response);
          pthread_cond_broadcast(&c_serve_response);
	  //wait = 0; 
     }
     PRN("exit\n");
     FFLUSH(Log);
     return 0;
}

void* serve_network(void *a)
{
     OPEN_THREAD_LOG_FILE();     
     PRN("enter\n");
     CMrun_network(cm);
     PRN("exit\n");
     return 0;
}

void* serve_query(void *a)
{
     OPEN_THREAD_LOG_FILE();
     PRN("enter\n");
     char action[15]="";
     char name[NAME_MAX_LEN]="";
     char value[VALUE_MAX_LEN]="";
     char key[KEY_HEX_LEN]="";
     char successor_key[KEY_HEX_LEN]="";
     char successor_address[ADDRESS_LEN]="";
     simple_rec request_data;
     memset(&request_data, 0, sizeof(request_data));
     
     char *ptr;
     int count;
     while(1)
     {
	  //fprintf(stdout, "'put <name> <value>' to store data\n");
	  fprintf(stdout, "'get <name>' to retrieve data\n");
	  fprintf(stdout, "'dumptable' to show all data stored at this node\n");
	  fgets(name, NAME_MAX_LEN, stdin);
	  
	  ptr = name;
	  count = 0;
	  while( (*ptr != ' ') && (*ptr != '\0') && (*ptr != '\n'))
	  {
	       action[count] = *ptr++;
	       count++;	       
	  }
	  action[count] = '\0';
	  ++ptr;
	  PRN("action=[%s]\n", action);
     
#if 0
	  if(0 == strcmp(action, "put"))
	  {
	       PRN("Inside put\n");
	       if(0 == strcmp(ft.node_address, successor_address))
	       {
		 put_data(table, ft.node_address, name, value);
	       }
	       else
	       {
		    /* remotely invoke update_finger_table */
		    request_data.function_name = "put_data";
		    request_data.function_type = Put_Data;
		    request_data.key = ft.node_address;
		    request_data.name = name;                   
		    request_data.value = value;                
		    request_data.address = ft.node_address;
		    request_data.request_response_type = Request;
		    Send(&request_data, successor_address);
	       }
	       FFLUSH(Log);
	  }
#endif
	  if(0 == strcmp(action, "get"))
	  {
	       PRN("Inside get\n");
	       count = 0;
	       while( ptr[count] != '\n' && ptr[count] != '\0')
	       {
		    count++;
	       }
	       ptr[count] = '\0';
	       key_compute(ptr, key);
	       find_successor(key, successor_key, successor_address);
	       
	       PRN("name=[%s] key=[%s] successor_key=[%s] successor_address=[%s]\n", ptr, key, successor_key, successor_address);

	       if(0 == strcmp(ft.node_address, successor_address))
	       {
		    get_data(table, NULL, ptr, value);
		    fprintf(stdout, "Got value = [%s]\n", value);
	       }
	       else
	       {
		    /* remotely invoke update_finger_table */
		    request_data.function_name = "get_data";
		    request_data.function_type = Get_Data;
		    request_data.key = NULL;
		    request_data.name = ptr;
		    request_data.address = ft.node_address;
		    request_data.request_response_type = Request;
		    request_data.thread_id = pthread_self();
		    //wait = 1;
		    Send(&request_data, successor_address);
		    
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
		    
		    fprintf(stdout, "Got value = [%s]\n", response_data.value);
		    pthread_mutex_unlock(&m_response);
	       }
	       PRN("Got value=[%s]\n", response_data.value);
	       FFLUSH(Log);
	  }
	  else if(0 == strcmp(action, "dumptable"))
	  {
	       hash_dump(table);
	  }
	  else
	  {
	       fprintf(stdout, "incorrect action=[%s] ...try again\n");
	  }
     }
     PRN("exit\n");
     return 0;
}

void* stabilize_finger_table(void *a)
{
  OPEN_THREAD_LOG_FILE();
  PRN("enter\n");
  simple_rec request_data;
  int condition;
  char response_key[KEY_HEX_LEN]="";
  char response_address[ADDRESS_LEN]="";
  
  while(1)
  {
       if(0 != strcmp(ft.node_address, ft.finger[0].successor_address))
       {
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
	    strcpy(response_key, response_data.key);
	    strcpy(response_address, response_data.address);
	    pthread_mutex_unlock (&m_response);

	    condition = 0;
	    if(key_compare(ft.node_key, ft.finger[0].successor_key) < 0)
	    {
		 condition = (key_compare(response_key, ft.node_key) > 0) && (key_compare(response_key, ft.finger[0].successor_key) < 0);
	    }
	    else
	    {
		 condition = (key_compare(response_key, ft.node_key) > 0) || (key_compare(response_key, ft.finger[0].successor_key) < 0);
	    }

	    /*update its successor*/
	    if(condition)
	    {
		 PRN("updating successor\n");
		 pthread_mutex_lock(&m_finger_table);
		 strcpy(ft.finger[0].successor_key, response_key);
		 strcpy(ft.finger[0].successor_address, response_address);
		 pthread_mutex_unlock(&m_finger_table);
	    
		 /*notify its latest successor that this node might be its predecessor*/
		 /*remotely invoke check_update_predecessor*/
		 memset(&request_data, 0, sizeof(request_data));
		 request_data.function_name = "check_update_predecessor";
		 request_data.function_type = Check_Update_Predecessor;
		 request_data.key = ft.node_key;
		 request_data.address = ft.node_address;
		 request_data.request_response_type = Request;
		 Send(&request_data, ft.finger[0].successor_address);
	    }
       }

       /*Need to do stabilization periodically*/
       sleep(90);
  } 
  PRN("exit\n");
  return 0;   
}

void close_log(void * thread_log)
{
  fclose((FILE*) thread_log);
}

int main(int argc, char** argv )
{
     gen_pthread_init();

     pthread_key_create(&log_key, NULL);
     
     OPEN_THREAD_LOG_FILE();

     PRN("enter\n");
     memset(&list, 0, sizeof(list));
     memset(&ft, 0, sizeof(ft));
     table = new_hash_table();
     table->hash_count = DEFAULT_HASH_SIZE;
     memset(&response_data, 0, sizeof(response_data));
     char response_key[KEY_HEX_LEN] = "";
     char response_address[ADDRESS_LEN] = "";
     char response_value[VALUE_MAX_LEN]="";
     response_data.address = response_address;
     response_data.key = response_key;
     response_data.value = response_value;
     initQueue(&q_request);

#if 0
     /*Block SIGINT*/
     sigset_t sigs_to_block;
     sigemptyset(&sigs_to_block);   
     sigaddset(&sigs_to_block, SIGINT);  
     sigaddset(&sigs_to_block, SIGSEGV);  
     pthread_sigmask(SIG_BLOCK, &sigs_to_block, NULL); 
#endif
     
     int i;                                          //counter for request serving thread creation
     pthread_t *tid;                                 //thread identifier array
     tid =(pthread_t *) malloc(NUM_THREADS * sizeof(pthread_t));
     pthread_attr_t custom_sched_attr;
     pthread_attr_init(&custom_sched_attr);
     /* create the threads */
     for(i = 0; i < NUM_THREADS; i++)
     {
	  if (pthread_create(&tid[i], &custom_sched_attr, serve_request, NULL) != 0)
	  {
	       fprintf (stderr, "Unable to create worker thread\n");
	       exit (1);
	  }
     }

     cm = CManager_create();
     CMlisten(cm);

     EVstone stone;
     stone = EValloc_stone(cm);
     EVassoc_terminal_action(cm, stone, simple_format_list, simple_handler, NULL);

     char* string_list="";
     char node_address[ADDRESS_LEN];
     string_list = attr_list_to_string(CMget_contact_list(cm));
     sprintf(node_address, "%d:%s", stone, string_list);
     printf("Contact list \"%d:%s\"\n", stone, string_list);

     pthread_t tid1;
     pthread_create(&tid1, NULL, serve_network, NULL);


     if(argc == 1)
     {
       PRN("First node joining network\n");
       join(node_address, NULL);
     }
     else if(argc == 2)
     {
       PRN("Joing existing network\n");
       join(node_address, argv[1]);
     }
     else
     {
	  printf("usage 1: ./a.out\n");
	  printf("usage 2: ./a.out <existing_node_address>\n");
	  exit(1);
     }

     log_finger_table();

     if(argc == 2)
     {
	  PRN("\nSend message to the other node to log its finger table\n");
	  /*make the other node log its finger table*/
	  simple_rec request_data;
	  memset(&request_data, 0, sizeof(request_data));
	  request_data.function_name = "log_finger_table";
	  request_data.function_type = Log_Finger_Table;
	  request_data.address = ft.node_address;
	  request_data.request_response_type = Request;
	  Send(&request_data, argv[1]);
	  FFLUSH(Log);
     }

     PRN("Join over ... waiting to serve network\n");     
     printf("Join over ...waiting to serve network\n");


     pthread_t tid2;
     pthread_create(&tid1, NULL, serve_query, NULL);

     pthread_t tid3;
     pthread_create(&tid3, NULL, stabilize_finger_table, NULL);

     pthread_t tid4;
     pthread_create(&tid4, NULL, get_store_data, NULL);

     pthread_t tid5;
     pthread_create(&tid5, NULL, delete_stale_data, NULL);

#if 0
     /*Handle C-c*/
     sigset_t sigs_to_catch;  
     int caught;  
     sigemptyset(&sigs_to_catch);  
     sigaddset(&sigs_to_catch, SIGINT);  
     sigaddset(&sigs_to_catch, SIGSEGV);  
     PRN("waiting for SIGINT\n");
     sigwait(&sigs_to_catch, &caught);   
     PRN("Got SIGINT ..Log and Abort\n");
     FFLUSH(Log);
     exit(1);
#endif


     pthread_join(tid1, NULL);
     pthread_join(tid2, NULL);
     pthread_join(tid3, NULL);
     pthread_join(tid4, NULL);
     pthread_join(tid5, NULL);
     return 0;
}
