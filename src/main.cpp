#include <iostream>
#include <sys/wait.h>
#include <unistd.h>
using namespace std;

int main(){
    pid_t pid = fork();
    if(pid == 0){
        cout << "i am child process\n";
        cout << "i am child process1\n";
        cout << "i am child process2\n";
        cout << "my pid: " << getpid() << "\n";
    }
    else{
        cout << "i am parent. child pid: " << pid << "\n";
        wait(NULL);
    }
    return 0;
}

//fork() - creates child process
    //mutex
    // thread 1 -> compile
    //mutex
    // thread 2 -> run
        // 10 program -> thread 3
        // 10 program -> thread 4
// done()
