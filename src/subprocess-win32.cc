// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "subprocess.h"

#include <assert.h>
#include <stdio.h>

#include <algorithm>
#include <regex>

#include "util.h"

using namespace std;

Subprocess::Subprocess(bool use_console) : child_(NULL) , overlapped_(),
                                           is_reading_(false),
                                           use_console_(use_console) {
}

Subprocess::~Subprocess() {
  if (pipe_) {
    if (!CloseHandle(pipe_))
      Win32Fatal("CloseHandle");
  }
  // Reap child if forgotten.
  if (child_)
    Finish();
}

HANDLE Subprocess::SetupPipe(HANDLE ioport) {
  char pipe_name[100];
  snprintf(pipe_name, sizeof(pipe_name),
           "\\\\.\\pipe\\ninja_pid%lu_sp%p", GetCurrentProcessId(), this);

  pipe_ = ::CreateNamedPipeA(pipe_name,
                             PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_BYTE,
                             PIPE_UNLIMITED_INSTANCES,
                             0, 0, INFINITE, NULL);
  if (pipe_ == INVALID_HANDLE_VALUE)
    Win32Fatal("CreateNamedPipe");

  if (!CreateIoCompletionPort(pipe_, ioport, (ULONG_PTR)this, 0))
    Win32Fatal("CreateIoCompletionPort");

  memset(&overlapped_, 0, sizeof(overlapped_));
  if (!ConnectNamedPipe(pipe_, &overlapped_) &&
      GetLastError() != ERROR_IO_PENDING) {
    Win32Fatal("ConnectNamedPipe");
  }

  // Get the write end of the pipe as a handle inheritable across processes.
  HANDLE output_write_handle =
      CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  HANDLE output_write_child;
  if (!DuplicateHandle(GetCurrentProcess(), output_write_handle,
                       GetCurrentProcess(), &output_write_child,
                       0, TRUE, DUPLICATE_SAME_ACCESS)) {
    Win32Fatal("DuplicateHandle");
  }
  CloseHandle(output_write_handle);

  return output_write_child;
}

// http://alter.org.ua/en/docs/win/args/
static PCHAR* CommandLineToArgvA(PCHAR CmdLine, int* _argc)
{
    PCHAR* argv;
    PCHAR  _argv;
    ULONG  len;
    ULONG  argc;
    CHAR   a;
    ULONG  i, j;

    BOOLEAN  in_QM;
    BOOLEAN  in_TEXT;
    BOOLEAN  in_SPACE;

    len = strlen(CmdLine);
    i = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

    argv = (PCHAR*)GlobalAlloc(GMEM_FIXED, i + (len + 2) * sizeof(CHAR));

    _argv = (PCHAR)(((PUCHAR)argv) + i);

    argc = 0;
    argv[argc] = _argv;
    in_QM = FALSE;
    in_TEXT = FALSE;
    in_SPACE = TRUE;
    i = 0;
    j = 0;

    while (a = CmdLine[i]) {
        if (in_QM) {
            if (a == '\"') {
                in_QM = FALSE;
            }
            else {
                _argv[j] = a;
                j++;
            }
        }
        else {
            switch (a) {
            case '\"':
                in_QM = TRUE;
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                in_SPACE = FALSE;
                break;
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                if (in_TEXT) {
                    _argv[j] = '\0';
                    j++;
                }
                in_TEXT = FALSE;
                in_SPACE = TRUE;
                break;
            default:
                in_TEXT = TRUE;
                if (in_SPACE) {
                    argv[argc] = _argv + j;
                    argc++;
                }
                _argv[j] = a;
                j++;
                in_SPACE = FALSE;
                break;
            }
        }
        i++;
    }
    _argv[j] = '\0';
    argv[argc] = NULL;

    (*_argc) = argc;
    return argv;
}

// Function that will be executed in the new thread
struct ThreadFunctionParams
{
  Subprocess* subprocess;
  std::string command;
  HANDLE child_pipe;
};
DWORD WINAPI Subprocess::ThreadFunction(LPVOID lpParam)
{
    ThreadFunctionParams* threadParams = (ThreadFunctionParams*)lpParam; // Cast the parameter back to the correct type

    DWORD exitStatus = 0;

    int nArgs;
    PCHAR *szArglist = CommandLineToArgvA((PCHAR)threadParams->command.data(), &nArgs);
    if (szArglist == nullptr)
    {
        threadParams->subprocess->buf_ = "CommandLineToArgvA failed: Wut?\n";
        exitStatus = GetLastError();
    }
    else if(nArgs >= 2)
    {
        PCHAR procedure_name = szArglist[0];
        PCHAR module_path = szArglist[1];
        HMODULE hModule = LoadLibraryA(module_path);
        if (hModule == NULL)
        {
            threadParams->subprocess->buf_ = "LoadLibraryA failed: Couldn't find the module '";
            threadParams->subprocess->buf_ += module_path;
            threadParams->subprocess->buf_ += "'\n";
            exitStatus = GetLastError();
        }
        else
        {
            FARPROC procedure = GetProcAddress(hModule, procedure_name);
            if(procedure)
            {
              DWORD (*entry)(int nArgs, PCHAR *szArglist) = reinterpret_cast<decltype(entry)>(procedure);
              exitStatus = entry(nArgs - 2, szArglist + 2);
            }
            else {
              threadParams->subprocess->buf_ =
                  "LoadLibraryA failed: Couldn't find the procedure '";
              threadParams->subprocess->buf_ += procedure_name;
              threadParams->subprocess->buf_ += "'\n";
              exitStatus = ERROR_PROC_NOT_FOUND;
            }

            // FreeLibrary(hModule); // #TODO: Correctly free library
        }
        
    }
    else
    {   
        threadParams->subprocess->buf_ = "Not enough arguments from CommandLineToArgvA\n";
        exitStatus = ERROR_MOD_NOT_FOUND;
    }

    long event_index = InterlockedIncrementAcquire(
        &const_cast<Subprocess*>(threadParams->subprocess)->thread_event_count);
    (void)event_index;

    HANDLE pipe = threadParams->subprocess->pipe_;
    threadParams->subprocess->pipe_ = NULL;
    CloseHandle(pipe);

    if (threadParams->child_pipe)
        CloseHandle(threadParams->child_pipe);

    if (!PostQueuedCompletionStatus(SubprocessSet::ioport_, 0,
                                    (ULONG_PTR)threadParams->subprocess, NULL))
        Win32Fatal("PostQueuedCompletionStatus");

    LocalFree(szArglist);
    delete threadParams;

    return exitStatus;
}

bool Subprocess::Start(SubprocessSet* set, const string& command) {
  HANDLE child_pipe = SetupPipe(set->ioport_);

  // Define a regular expression pattern
  static std::regex frontend_pattern(R"(\s*^thread_frontend:\s*(.+)$)");
  std::smatch match;
  if (std::regex_match(command, match, frontend_pattern))
  {
    ThreadFunctionParams* threadParam = new ThreadFunctionParams();
    threadParam->subprocess = this;
    threadParam->command = match[1];

    // Create a thread and pass the parameter
    HANDLE hThread;
    DWORD dwThreadId;
    hThread = CreateThread(
        NULL,                   // Default security attributes
        0,                      // Default stack size
        ThreadFunction,         // Thread function to execute
        threadParam,                // Parameter to pass to the thread function
        0,                      // Default creation flags
        &dwThreadId             // Variable to receive the thread ID
    );
    if(hThread == NULL)
    {
      if (child_pipe)
        CloseHandle(child_pipe);

      delete threadParam;

      //DWORD error = GetLastError();
      buf_ = "CreateThread failed: Somebody find Bill Gates quick!\n";
      Win32Fatal("CreateThread", "Somebody find Bill Gates quick!");
    }

    is_thread = true;
    child_ = hThread;

    return true;
  }

  SECURITY_ATTRIBUTES security_attributes;
  memset(&security_attributes, 0, sizeof(SECURITY_ATTRIBUTES));
  security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  security_attributes.bInheritHandle = TRUE;
  // Must be inheritable so subprocesses can dup to children.
  HANDLE nul =
      CreateFileA("NUL", GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  &security_attributes, OPEN_EXISTING, 0, NULL);
  if (nul == INVALID_HANDLE_VALUE)
    Fatal("couldn't open nul");

  STARTUPINFOA startup_info;
  memset(&startup_info, 0, sizeof(startup_info));
  startup_info.cb = sizeof(STARTUPINFO);
  if (!use_console_) {
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = nul;
    startup_info.hStdOutput = child_pipe;
    startup_info.hStdError = child_pipe;
  }
  // In the console case, child_pipe is still inherited by the child and closed
  // when the subprocess finishes, which then notifies ninja.

  PROCESS_INFORMATION process_info;
  memset(&process_info, 0, sizeof(process_info));

  // Ninja handles ctrl-c, except for subprocesses in console pools.
  DWORD process_flags = use_console_ ? 0 : CREATE_NEW_PROCESS_GROUP;

  // Do not prepend 'cmd /c' on Windows, this breaks command
  // lines greater than 8,191 chars.
  if (!CreateProcessA(NULL, (char*)command.c_str(), NULL, NULL,
                      /* inherit handles */ TRUE, process_flags,
                      NULL, NULL,
                      &startup_info, &process_info)) {
    DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND) {
      // File (program) not found error is treated as a normal build
      // action failure.
      if (child_pipe)
        CloseHandle(child_pipe);
      CloseHandle(pipe_);
      CloseHandle(nul);
      pipe_ = NULL;
      // child_ is already NULL;
      buf_ = "CreateProcess failed: The system cannot find the file "
          "specified.\n";
      return true;
    } else {
      fprintf(stderr, "\nCreateProcess failed. Command attempted:\n\"%s\"\n",
              command.c_str());
      const char* hint = NULL;
      // ERROR_INVALID_PARAMETER means the command line was formatted
      // incorrectly. This can be caused by a command line being too long or
      // leading whitespace in the command. Give extra context for this case.
      if (error == ERROR_INVALID_PARAMETER) {
        if (command.length() > 0 && (command[0] == ' ' || command[0] == '\t'))
          hint = "command contains leading whitespace";
        else
          hint = "is the command line too long?";
      }
      Win32Fatal("CreateProcess", hint);
    }
  }

  // Close pipe channel only used by the child.
  if (child_pipe)
    CloseHandle(child_pipe);
  CloseHandle(nul);

  CloseHandle(process_info.hThread);
  child_ = process_info.hProcess;

  return true;
}

void Subprocess::OnPipeReady() {
  if (is_thread)
    return;

  DWORD bytes;
  if (!GetOverlappedResult(pipe_, &overlapped_, &bytes, TRUE)) {
    if (GetLastError() == ERROR_BROKEN_PIPE) {
      CloseHandle(pipe_);
      pipe_ = NULL;
      return;
    }
    Win32Fatal("GetOverlappedResult");
  }

  if (is_reading_ && bytes)
    buf_.append(overlapped_buf_, bytes);

  memset(&overlapped_, 0, sizeof(overlapped_));
  is_reading_ = true;
  if (!::ReadFile(pipe_, overlapped_buf_, sizeof(overlapped_buf_),
                  &bytes, &overlapped_)) {
    if (GetLastError() == ERROR_BROKEN_PIPE) {
      CloseHandle(pipe_);
      pipe_ = NULL;
      return;
    }
    if (GetLastError() != ERROR_IO_PENDING)
      Win32Fatal("ReadFile");
  }

  // Even if we read any bytes in the readfile call, we'll enter this
  // function again later and get them at that point.
}

ExitStatus Subprocess::Finish() {
  if (!child_)
    return ExitFailure;

  // TODO: add error handling for all of these.
  WaitForSingleObject(child_, INFINITE);

  DWORD exit_code = 0;
  if (is_thread)
    GetExitCodeThread(child_, &exit_code);
  else
    GetExitCodeProcess(child_, &exit_code);

  CloseHandle(child_);
  child_ = NULL;

  return exit_code == 0              ? ExitSuccess :
         exit_code == CONTROL_C_EXIT ? ExitInterrupted :
                                       ExitFailure;
}

bool Subprocess::Done() const {
  if (is_thread)
  {
    long event_index = InterlockedIncrementAcquire(
        &const_cast<Subprocess*>(this)->thread_event_count);
    return event_index == 3;
  }
  return pipe_ == NULL;
}

const string& Subprocess::GetOutput() const {
  return buf_;
}

HANDLE SubprocessSet::ioport_;

SubprocessSet::SubprocessSet() {
  ioport_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if (!ioport_)
    Win32Fatal("CreateIoCompletionPort");
  if (!SetConsoleCtrlHandler(NotifyInterrupted, TRUE))
    Win32Fatal("SetConsoleCtrlHandler");
}

SubprocessSet::~SubprocessSet() {
  Clear();

  SetConsoleCtrlHandler(NotifyInterrupted, FALSE);
  CloseHandle(ioport_);
}

BOOL WINAPI SubprocessSet::NotifyInterrupted(DWORD dwCtrlType) {
  if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
    if (!PostQueuedCompletionStatus(ioport_, 0, 0, NULL))
      Win32Fatal("PostQueuedCompletionStatus");
    return TRUE;
  }

  return FALSE;
}

Subprocess *SubprocessSet::Add(const string& command, bool use_console) {
  Subprocess *subprocess = new Subprocess(use_console);
  if (!subprocess->Start(this, command)) {
    delete subprocess;
    return 0;
  }
  if (subprocess->child_)
    running_.push_back(subprocess);
  else
    finished_.push(subprocess);
  return subprocess;
}

bool SubprocessSet::DoWork() {
  DWORD bytes_read;
  Subprocess* subproc;
  OVERLAPPED* overlapped;

  if (!GetQueuedCompletionStatus(ioport_, &bytes_read, (PULONG_PTR)&subproc,
                                 &overlapped, INFINITE)) {
    if (GetLastError() != ERROR_BROKEN_PIPE)
      Win32Fatal("GetQueuedCompletionStatus");
  }

  if (!subproc) // A NULL subproc indicates that we were interrupted and is
                // delivered by NotifyInterrupted above.
    return true;

  subproc->OnPipeReady();

  if (subproc->Done()) {
    vector<Subprocess*>::iterator end =
        remove(running_.begin(), running_.end(), subproc);
    if (running_.end() != end) {
      finished_.push(subproc);
      running_.resize(end - running_.begin());
    }
  }

  return false;
}

Subprocess* SubprocessSet::NextFinished() {
  if (finished_.empty())
    return NULL;
  Subprocess* subproc = finished_.front();
  finished_.pop();
  return subproc;
}

void SubprocessSet::Clear() {
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i) {
    // Since the foreground process is in our process group, it will receive a
    // CTRL_C_EVENT or CTRL_BREAK_EVENT at the same time as us.
    if ((*i)->child_ && !(*i)->use_console_) {
      if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,
                                    GetProcessId((*i)->child_))) {
        Win32Fatal("GenerateConsoleCtrlEvent");
      }
    }
  }
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i)
    delete *i;
  running_.clear();
}
