#include <stdio.h>
#include <mariadb/mysql.h>
#include <string.h>
#include <stdlib.h>


int main(int argc , char** argv) {

	MYSQL	*connection=NULL, conn;
	MYSQL_RES	*sql_result;
	MYSQL_ROW	sql_row;
	int	query_stat;
	//char query_string[200] = {};
	char *query_string = NULL;

	int i = 0;
	int j = 0;
	
	int values_cnt = 1;
	int loop_cnt = 10;
	
	printf("INFO: argc = %d\n" , argc);
	
	for ( i = 0 ; i < argc ; i++ )
	{
		printf("INFO: argv[%d] == \"%s\".\n", 
				i , argv[i]);
	}
	
	if ( argc >= 2 ) 
	{
		values_cnt = atoi ( argv[1] ) ;
	}
	if ( argc >= 3 )
	{
		loop_cnt = atoi ( argv[2] ) ;
	}
	
	printf("INFO: (int)argv[1] == \"%d\".\n", 
				 values_cnt);
	printf("INFO: (int)argv[2] == \"%d\".\n", 
				 loop_cnt);
	
		
	
	
	
	// column list
	//
	//MariaDB [project_db]> desc tb_member_list ;
        //+----------mysql.h+--------+------+-----+---------+----------------+
       //| Field | Type | Null | Key | Default | Extra |
        //+----------+--------+------+-----+---------+----------+
       //| id | bigint(20) | NO | PRI | NULL| auto_increment |
        //| name     | varchar(100) | YES  |     | NULL            |                |
        //| age      | int(11)      | YES  |     | NULL            |                |
       // | address  | varchar(100) | YES  |     | NULL            |                |
        //| phone    | varchar(100) | YES  |     | NULL            |                |
       // | descript | varchar(100) | YES  |     | NULL            |                |
        //+----------+--------------+------+-----+---------        +----------------+
        //6 rows in set (0.001 sec)
        
        //MariaDB [project_db]> 
	        
	int id = 0;
	char name[100] = {};
	int age = 0;
	char address[100] = {};
	char phone[100] = {};
	char descript[100] = {};

	printf("INFO: begin program\n");
	
	mysql_init(&conn);
	
	connection = mysql_real_connect(
			&conn,	// mysql handler
			"localhost",	// host
			"root",	// id
			"rootpass",	// pw
			"project_db",	// db_name
			3306,		// port
			(char*)NULL,	// 
			0		// 
		);

	if ( connection == NULL ) {
		fprintf(stderr, "ERROR: "
			"Mysql connection error: %s",
			mysql_error(&conn));
		return 1;
	}

	query_string = malloc(10485760);

	memset( query_string , 0x00 , 10485760);
	

	sprintf(query_string,
		"INSERT INTO tb_member_list "
		"(name , age , address , phone , descript )"
		" VALUES "
		"( '%s' , %d , '%s' , '%s' , '%s' )" , 
		
		"cha" , 20 , "usa" , "010-0000-0000" , "" );
	for ( i = 1 ; i < values_cnt ; i++ )
	{
		strcat( query_string, 
			", ( 'kang' , 22 , 'italia' ,"
				" '010-1010-2020' , '' )"
		);
	}

	// begin of loop_cnt loop .
	for ( j = 0 ; j < loop_cnt ; j++ )
	{
		query_stat = mysql_query( connection, 
						query_string );
		if ( query_stat != 0 ) {
			fprintf( stderr, "ERR: Mysql query"
						" error : %s",
			mysql_error(&conn) );
			return 1;
		} else {
			fprintf( stdout, "NOTICE: "
					"insert OK.\n" );
		}
	}
	// end of loop_cnt loop .
	
	//sql_result = mysql_store_result(connection);
	
	//while ( (sql_row = mysql_fetch_row(sql_result)) 
	//		!= NULL ) 
	//{
	//	printf( "%s\t%s\t%s\t%s\t%s\t%s\n", 
	//	sql_row[0], sql_row[1], sql_row[2], 
	//	sql_row[3], sql_row[4], sql_row[5] );
	//}
	
	free(query_string);
	
	// begin comment out using if .
	if ( 0 ) {
	
	if ( sql_result != NULL ) 
	{
		mysql_free_result(sql_result);
		sql_result = NULL;
	} else {
		fprintf(stderr,
			"WARNING: "
			"sql_result is already free !!!\n");
	}
	// end of if - else .

	if ( sql_result != NULL ) 
	{
		mysql_free_result(sql_result);
		sql_result = NULL;
	} else {
		fprintf(stderr,
			"WARNING: "
			"sql_result is already free "
			"(%s:%d (%s))!!!\n",
			__FILE__, __LINE__ , __FUNCTION__);
	}
	// end of if - else .
		
	}
	// end comment out using if .
	
	return 0;

}
