#include <stdio.h>
#include <stdlib.h>

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

     while (i--) 
     {
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

     /*Search for existing name, update its value and return*/
     for(bp = table -> buckets [hashno]; bp; bp = bp -> next)
     {
	  if( 0 == strcmp(name, bp -> name))
	  {
	       if(strlen(bp->value) < strlen(value))
		    realloc(bp->value, strlen(value);
	       strcpy(bp -> value, value);
	       return;
	  }
     }

     /*else create new name-value pair*/
     if(NULL == table -> buckets [hashno])
     {
	  table -> key [hashno] = (char*)malloc(strlen(key));
	  assert(NULL != table ->key [hashno]);
	  strcpy(table -> key [hashno], key);
     }

     bp = (hash_bucket*) malloc(sizeof(hash_bucket));
     assert(NULL != bp);
     bp -> name = (char*)malloc(strlen(name));
     bp -> value = (char*)malloc(strlen(value));
     assert(NULL != bp -> name);
     assert(NULL != bp -> value);

     strcpy(bp -> name, name);
     strcpy(bp -> value, value);;
     bp -> next = table -> buckets [hashno];
     table -> buckets [hashno] = bp;
     
     PRN("exit\n");
}

void delete_hash_entry (hash_table* table, char* name)
{
     PRN("enter\n");

     assert(NULL != table);
     assert(NULL != name);

     int hashno;
     hash_bucket *bp, *pbp = (hash_bucket *)0;

     /* Go through the list looking for an entry that matches;
	if we find it, delete it. */
     for( hashno = 0; hashno < table -> hash_count; hashno++)
     {
	  for (bp = table -> buckets [hashno]; bp; bp = bp -> next) 
	  {
	       if (0 == strcmp ((char *)bp -> name, (char *)name)) 
	       {
		    if (pbp) 
		    {
			 pbp -> next = bp -> next;
		    } 
		    else 
		    {
			 table -> buckets [hashno] = bp -> next;
		    }
		    free (bp);
		    break;
	       }
	       pbp = bp;     
	  }
     }
     PRN("exit\n");
}

void hash_lookup (hash_table* table, char* key, char* name, char* value)
{
     PRN("enter\n");

     assert(NULL != table);
     assert(NULL != name);

     int hashno;
     hash_bucket *bp;
     int len=0;
     char buff[512]="";

     if(key)
     {
	  PRN("inside key\n");
	  hashno = do_hash (key, strlen(key), table -> hash_count);
	  for (bp = table -> buckets [hashno]; bp; bp = bp -> next) 
	  {
	       PRN("inside for\n");
	       if (0 == strcmp (bp -> name, name))
	       {
		    printf("value = [%s]\n", bp -> value);
		    sprintf(value, "%s %s\n", table->key[hashno], bp->next);
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
		    printf("value = [%s]\n", bp -> value);
		    len = len + strlen(table->key[hashno]) + strlen(bp->value);
		    assert(len <= VALUE_MAX_LEN);
		    sprintf(buff, "%s %s\n", table->key[hashno], bp->next);
		    strcat(value, buff);
	       }
	  }
	  PRN("final value=[%s]\n", value);
     }
     PRN("exit\n");
}

void hash_dump (hash_table* table)
{
     PRN("enter\n");
     int i;
     hash_bucket *bp;

     assert(NULL != table);

     for (i = 0; i < table -> hash_count; i++) 
     {
	  if (!table -> buckets [i])
	       continue;

	  printf("hash bucket %d key %s \n", i, table -> key[i]);
	  for (bp = table -> buckets [i]; bp; bp = bp -> next) 
	  {
	       printf("%s %s", bp -> name, bp -> value);
	  }
     }
     PRN("exit\n");
}
