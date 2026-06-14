#include <stdlib.h>
#include<stdio.h>


char* stringSanitizer(char* unsafeString) { 

	int i = 0; 
	while(unsafeString[i] != '\0') { 

		if(unsafeString[i] == 'a') { 

			unsafeString[i] = '@';

		}
		i++;


	}
	return unsafeString;


}


int main() { 

	char myUnsafeString[] = "That cat is rallying rare rambunctious rascals.";
	printf("%s\n", stringSanitizer(myUnsafeString));

	return 0;
	 

}