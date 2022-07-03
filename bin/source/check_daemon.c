#include "system_program.h"

/*  A program that prints how many summoned daemons are currently alive */
int execute()
{

   // Create a command that trawl through output of ps -efj and contains "summond"
   char *command = malloc(sizeof(char) * 256);
   sprintf(command, "ps -efj | grep summond  | grep -Ev 'tty|pts' > output.txt");

   int result = system(command);
   if (result == -1)
   {
      printf("Command %s fail to execute. Exiting now. \n", command);
      return 1;
   }

   free(command);

   int live_daemons = 0;
   FILE *fptr;

   /* TASK 7 */
   // 1. Open the file output.txt
   // 2. Fetch line by line using getline()
   // 3. Increase the daemon count whenever we encounter a line
   // 4. Store the count inside live_daemons
   // DO NOT PRINT ANYTHING TO THE OUTPUT

   /***** BEGIN ANSWER HERE *****/
   fptr = fopen("output.txt", "r");

   size_t line_buf_size = SHELL_BUFFERSIZE;
   char *buffer = malloc(line_buf_size * sizeof(char));
   int count = 0;
   if (fptr != NULL)
   {
      int line_size;

      line_size = getline(&buffer, &line_buf_size, fptr);

      while (line_size != -1)
      {
         count++;
         line_size = getline(&buffer, &line_buf_size, fptr);
      }
   }
   live_daemons = count;
   /*********************/
   if (live_daemons == 0)
      printf("No daemon is alive right now.\n");
   else
   {
      printf("Live daemons: %d\n", live_daemons);
   }

   fclose(fptr);

   return 1;
}

int main(int argc, char **args)
{
   return execute();
}