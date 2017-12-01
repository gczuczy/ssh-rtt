#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#include <string>
#include <istream>
#include <sstream>
#include <chrono>
#include <vector>
#include <list>

static int ssh(const std::string &_target, int _stdin, int _stdout);
static void setnonblock(int _fd);
static uint64_t measure(int _stdin, int _stdout, std::string &_msg);
static bool endswidth(const std::string &_str, const std::string &_end);

int main(int argc, char *argv[]) {

  if ( argc != 2 ) {
    printf("Usage: %s <hostname>\n", argv[0]);
    return 1;
  }
  std::string target(argv[1]);

  printf("Target host: %s\n", target.c_str());

  int inpipefd[2];
  int outpipefd[2];
  pid_t childpid;

  // fd[0]: read end
  // fd[1]: write end
  pipe(inpipefd);
  pipe(outpipefd);
  setnonblock(inpipefd[0]);
  setnonblock(outpipefd[0]);

  // forking here, and inside dealing with the child process
  if ( (childpid = fork()) == 0 ) {
    int ret = ssh(target, inpipefd[0], outpipefd[1]);
    std::string errstr = "unknown";
    switch (errno) {
    case E2BIG: errstr = "E2BIG"; break;
    case EACCES: errstr = "EACCES"; break;
    case EAGAIN: errstr = "EAGAIN"; break;
    case EFAULT: errstr = "EFAULT"; break;
    case EINVAL: errstr = "EINVAL"; break;
    case EIO: errstr = "EIO"; break;
    case EISDIR: errstr = "EISDIR"; break;
    case ELIBBAD: errstr = "ELIBBAD"; break;
    case ELOOP: errstr = "ELOOP"; break;
    case EMFILE: errstr = "EMFILE"; break;
    case ENAMETOOLONG: errstr = "ENAMETOOLONG"; break;
    case ENFILE: errstr = "ENFILE"; break;
    case ENOENT: errstr = "ENOENT"; break;
    case ENOEXEC: errstr = "ENOEXEC"; break;
    case ENOMEM: errstr = "ENOMEM"; break;
    case ENOTDIR: errstr = "ENOTDIR"; break;
    case EPERM: errstr = "EPERM"; break;
    case ETXTBSY: errstr = "ETXTBSY"; break;
    }
    fprintf(stderr, "Child exit: %i/%i/%s/%s\n", ret, errno, errstr.c_str(), strerror(errno));
    return ret;
  }
  close(inpipefd[0]);
  close(outpipefd[1]);
  int ssh_stdin = inpipefd[1];
  int ssh_stdout = outpipefd[0];

  usleep(10000);

  std::string inbuf("");
  char buf[4096];
  int recvlen = 0;
  std::string str_loggedin("debug2: shell request accepted on channel 0");
  bool loggedin(false);
  while (!loggedin) {
    
    recvlen = read(ssh_stdout, buf, sizeof(buf)-1);
    if ( recvlen > 0 ) {
      inbuf += std::string(buf, recvlen);
      std::istringstream ios(inbuf);
      std::string line;
      while ( std::getline(ios, line, '\n') ) {
	if ( line[line.length()-1] == '\r' ) {
	  line.pop_back();
	}
	//printf("line: '%s'\n", line.c_str());
	if ( line == str_loggedin ) loggedin = true;
      }
      if ( !loggedin ) inbuf = line;
    }

    usleep(10);
  }
  // now we are logged in here

  printf("Logged in, starting measurement\n");

  std::list<uint64_t> results;
  std::vector<std::string> teststrings{"A",
      "foobar",
      "a quick brown fox jumps over the lazy dog"};
  int iterations=10;
  for (int i=0; i<iterations; ++i) {
    printf("Iteration %i/%i\n", i+1, iterations);
    for (auto &it: teststrings) {
      uint64_t t = measure(ssh_stdin, ssh_stdout, it);
      results.push_back(t);
      printf("Len: %u time: %lu ms\n", it.length(), t);
    }
  }

  uint64_t avg = 0;
  for (auto &it: results) {
    avg += it;
  }
  avg /= results.size();
  printf("Average latency: %lu ms\n", avg);
  
  write(ssh_stdin, "logout\n", 7);
  wait(NULL);
  
  return 0;
}

int ssh(const std::string &_target, int _stdin, int _stdout) {
  dup2(_stdin, STDIN_FILENO);
  dup2(_stdout, STDOUT_FILENO);
  dup2(_stdout, STDERR_FILENO);

  char *argv[] = {"/usr/bin/ssh",
		  "-ttt",
		  "-q",
		  "-vv",
		  (char*)_target.c_str(),
		  (char*)0};
  char *envp[] = {
    "TERM=xterm",
    0,
    0};
  // SSH_AUTH_SOCK
  char *authsock = getenv("SSH_AUTH_SOCK");
  char env_authsock[1024];
  if ( authsock != 0 ) {
    snprintf(env_authsock, 1023, "SSH_AUTH_SOCK=%s", authsock);
    envp[1] = env_authsock;
  }

  return execve(argv[0], argv, envp);
}

void setnonblock(int _fd) {
  int flags;

  flags = fcntl(_fd, F_GETFL, 0);
  if ( flags >= 0 ) {
    fcntl(_fd, F_SETFL, flags | O_NONBLOCK);
  }
}

uint64_t measure(int _stdin, int _stdout, std::string &_msg) {
  std::string inbuf;

  char buf[1024];
  int len;
  len = snprintf(buf, 1023, "echo '%s'\n", _msg.c_str());
  std::string cmd(buf, len);
  std::string replystr(_msg);
  replystr += "\n";

  auto time_recv = std::chrono::high_resolution_clock::now();
  auto time_send = std::chrono::high_resolution_clock::now();
  write(_stdin, cmd.c_str(), cmd.length());
  while (true) {
    len = read(_stdout, buf, sizeof(buf)-1);
    if ( len > 0 ) {
      inbuf += std::string(buf, len);
      if ( endswidth(inbuf, replystr) ) {
	time_recv = std::chrono::high_resolution_clock::now();
	break;
      } else {
	printf("'%s' != 'foobar'\n", inbuf.c_str());
      }
    }
    usleep(1);
  }

  auto timediff = std::chrono::duration_cast<std::chrono::milliseconds>(time_recv - time_send);
  return timediff.count();
}

bool endswidth(const std::string &_str, const std::string &_end) {
  return true;
}
