

#include <string>
#include <iostream>
#include <thread>

using namespace std;

//The function we want to make the thread run.
void task(string msg)
{
	cout << msg << " running " << '\n';
	while(1);
}

int main()
{
	// Constructs the new thread and runs it. Does not block execution.
	thread t1(task, "Task1");
	thread t2(task, "Task2");
	
	//Makes the main thread wait for the new thread to finish execution, therefore blocks its own execution.
	t1.join();
	t2.join();
}



