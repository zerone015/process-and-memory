# process-and-memory
이 프로젝트는 주어진 PID에 대한 프로세스 정보를 반환하는 사용자 정의 시스템 콜을 리눅스 커널에 추가합니다.

## 실행 방법

1. x86 아키텍처 기반 리눅스 환경을 준비합니다.

2. 리눅스 6.18-rc3 소스 트리를 설치하고, 다음 경로에 둡니다.

   `/usr/src/kernel-6.18.0`

3. 새로 빌드된 커널로 부팅할 수 있도록 부트로더에 커널 이미지 엔트리를 추가합니다.  
   커널 이미지 이름은 다음과 같습니다.

   `vmlinuz-6.18.0-get-pid-info`

4. 프로젝트 루트에서 커널을 빌드하고 설치합니다.

   ```bash
   make
   ```

   위 명령은 커널 소스에 필요한 파일을 복사하고 커널을 빌드한 뒤,  
   새 커널을 설치하고 재부팅까지 자동으로 수행합니다.

5. 재부팅 후 부트로더에서 `vmlinuz-6.18.0-get-pid-info`로 부팅합니다.

6. 유저 공간 테스트 프로그램을 빌드하고 실행합니다.

   ```bash
   make tester
   ./test <pid>
   ```
   
## 과제 지침

- 리눅스 커널에 새로운 시스템 콜을 추가해야 합니다.
  - 유저 공간 이름: `get_pid_info`
  - 커널 내부 이름: `sys_get_pid_info`

- 시스템 콜 프로토타입:

  ```c
  long sys_get_pid_info(struct pid_info *ret, int pid);
  ```

- `struct pid_info`에는 다음 정보가 포함되어야 합니다.
  - 프로세스 PID
  - 프로세스 상태 (3가지 값 중 하나로 압축 표현)
  - 프로세스 스택 포인터
  - 프로세스 실행 이후 경과 시간(프로세스 age)
  - 자식 프로세스들의 PID 배열
  - 부모 프로세스의 PID
  - 프로세스의 root 경로
  - 프로세스의 PWD

- 커널 측 요구사항:
  - ft_linux 프로젝트에서 만든 커스텀 Linux 배포판을 사용해야 한다. 
  - 커널 버전은 4.0 이상이어야 한다.
  - 커널 공간에서 할당된 모든 메모리는 반드시 사용자 공간으로 올바르게 전달되어야 한다.
  - Makefile을 제출해야 한다.
  - 그 Makefile은 git 저장소에서 올바른 파일들을 `/usr/src/linux-$(VERSION)` 으로 복사하고,   
    커널을 컴파일하고, 커널을 올바른 위치로 이동시키고, 컴퓨터를 재부팅해야 한다.

- 유저 공간 요구사항:
  - 새로운 시스템 콜을 직접 호출하는 C 예제 프로그램을 제공해야 한다.
    - `/proc/<pid>`를 읽는 방식이 아닌, 반드시 `get_pid_info` 시스템 콜을 통해 정보를 가져와야 한다.
  - 예제 프로그램은:
    - 특정 PID에 대한 정보를 출력하고,
    - 부모/자식 프로세스를 따라 올라가거나 내려가며 정보를 출력할 수 있어야 한다.

## 시스템 콜 호출 흐름

리눅스에서 시스템 콜은 유저 공간에서 glibc 래퍼를 통해 호출되고,  
시스템 콜 번호와 인자를 레지스터에 담아 `int 0x80`/`sysenter`/`syscall` 명령으로 커널로 진입합니다.  
커널은 부팅 시 IDT에 시스템 콜용 게이트를 등록하고,  
각 진입 방식에 대응하는 MSR에 진입 함수 주소 등 필요한 정보를 설정하여,   
위와 같은 여러 진입 명령들을 통해 커널에 진입할 수 있도록 준비합니다.

x86-64에서는 커널 진입 후 제어 흐름이 `arch/x86/entry/`의 진입 코드에서 시작해  
사용자 모드 레지스터 값을 커널 스택에 저장하고 모드 전환 관련 처리 등을 수행한 뒤,  
이렇게 저장된 유저 문맥을 `struct pt_regs *regs` 포인터로 C 코드에 넘겨서  
최종적으로 `x64_sys_call(const struct pt_regs *regs, unsigned int nr)` 함수로 이어집니다:

```c
#define __SYSCALL(nr, sym) case nr: return __x64_##sym(regs);

long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
    #include <asm/syscalls_64.h>
	default:
		return __x64_sys_ni_syscall(regs);
	}
}
```

여기서 포함하는 `syscalls_64.h`는 빌드 시  
`scripts/syscalltbl.sh`가 `arch/x86/entry/syscalls/syscall_64.tbl`을 읽어서 자동으로 생성하는 헤더이며,  
`arch/x86/include/generated/asm/syscalls_64.h` 경로에 만들어집니다.  
실제 파일에는 모든 시스템 콜에 대한 항목이 들어가며, 그중 일부 예시는 다음과 같습니다:

```c
/* arch/x86/include/generated/asm/syscalls_64.h  */
...
__SYSCALL(468, sys_file_getattr)
__SYSCALL(469, sys_file_setattr)
__SYSCALL(470, sys_get_pid_info)
```

이 프로젝트에서 추가한 `sys_get_pid_info`도 이 흐름을 그대로 따릅니다.  
`syscall_64.tbl`에 번호를 추가하고 커널에서 `SYSCALL_DEFINE2(get_pid_info, ...)`로 구현을 작성하면,  
빌드 시 `syscalls_64.h`에 `__SYSCALL(470, sys_get_pid_info)` 같은 엔트리가 생기고,  
최종적으로 `x64_sys_call()`의 `switch (nr)` 분기에서 `__x64_sys_get_pid_info(regs)`가 호출됩니다.  
여기서 `__x64_sys_get_pid_info()`는 `SYSCALL_DEFINE2(get_pid_info, ...)` 매크로가 만들어 주는 stub 함수로,  
`pt_regs`에 저장된 레지스터 값들에서 인자를 꺼내어 실제 `sys_get_pid_info()` 커널 구현을 호출하는 역할을 합니다.

시스템 콜 처리가 끝나면 커널은 `pt_regs`에 보관해 둔 사용자 모드 레지스터 값을 복원하고,  
필요한 후처리를 수행한 뒤, `iret`/`sysexit`/`sysret` 명령을 통해 다시 유저 공간으로 복귀합니다.


## sys_get_pid_info 구현

프로세스의 정보는 대부분 `task_struct`에 들어 있습니다.  
따라서 먼저 PID로 `task_struct`를 찾아와야 합니다.

```c
tsk = find_get_task_by_vpid(pid);
```

`find_get_task_by_vpid()`는 내부적으로 RCU 보호 하에서 PID를 검색하고,  
찾은 `task_struct`의 참조 카운트를 증가시켜 반환합니다.  
참조 카운트를 증가시켰기 때문에, 사용이 끝나면 `put_task_struct()`로 감소시켜야 합니다.

RCU reader-side critical section 안에서 참조 카운트 없이 `task_struct`를 사용하는 방법도 있지만,  
이 경우 내부에서 sleep을 할 수 없고,  
reader 구간이 길어질수록 RCU writer나 콜백 처리 지연과 같은 부작용이 커질 수 있습니다.

### PID 채우기

```c
static void fill_pid(struct pid_info *info, int pid)
{
    info->pid = pid;
}
```

요청받은 PID 자체를 그대로 저장합니다.

### 상태 채우기

```c
static void fill_state(struct pid_info *info, struct task_struct *tsk)
{
    if (READ_ONCE(tsk->exit_state) & EXIT_TRACE)
        info->state = PID_STATE_ZOMBIE;
    else if (READ_ONCE(tsk->__state) == TASK_RUNNING)
        info->state = PID_STATE_RUNNING;
    else
        info->state = PID_STATE_SLEEPING;
}
```

리눅스에는 더 많은 태스크 상태가 존재하지만,  
과제 요구사항에 따라 3가지 상태로 압축했습니다.

- `PID_STATE_ZOMBIE` : `exit_state`에 `EXIT_TRACE`가 설정된 경우
- `PID_STATE_RUNNING` : `__state == TASK_RUNNING`
- 그 외는 모두 `PID_STATE_SLEEPING`으로 취급

`exit_state`와 `__state`는 동시에 접근될 수 있고, 특히 `__state`는 자주 변경되는 필드입니다.  
따라서 `READ_ONCE()`로 읽어 컴파일러 최적화에 의한 이상 동작을 방지하고,  
이 필드를 읽을 때 원자적으로 동작하게 했습니다.

### 스택 포인터 채우기

```c
static void fill_sp(struct pid_info *info, struct task_struct *tsk)
{
    struct mm_struct *mm;

    mm = get_task_mm(tsk);

    if (!mm)
        return;

    info->sp = READ_ONCE(mm->start_stack);
    mmput(mm);
}
```

과제에서는 “Pointer to process’ stack. (RO in user space)”를 요구합니다.  
이 구현에서는 유저 공간 스택 주소를 사용했습니다.  
커널 스택 주소를 유저 공간에 노출할 필요는 없다고 판단했습니다.

`task_struct`의 `mm` 필드는 `task_lock`으로 보호되며, 참조 카운트로 생명주기가 관리됩니다.  
`get_task_mm()`는 내부적으로 락을 잡고 참조 카운트를 증가시킨 뒤 `mm`를 반환합니다.  
사용이 끝나면 반드시 `mmput()`으로 참조 카운트를 감소시켜야 하며,  
`mmput()`는 sleep 가능 함수이므로 원자적 컨텍스트에서는 사용할 수 없습니다.

### age 채우기

```c
static void fill_age(struct pid_info *info, struct task_struct *tsk)
{
    u64 now = ktime_get_ns();

    info->age = now - tsk->start_time;
}
```

프로세스가 `fork`로 생성될 때 `start_time`이 설정됩니다.  
현재 시각(`ktime_get_ns()`)과의 차이를 계산해 프로세스의 age를 나노초 단위로 저장합니다.

### 자식 리스트 채우기

```c
static void fill_children(struct pid_info *info, struct task_struct *tsk)
{
    struct task_struct *child;
    int i = 0;

    read_lock(&tasklist_lock);
    list_for_each_entry(child, &tsk->children, sibling) {
        if (i == MAX_CHILDREN)
            break;
        info->children[i++] = child->pid;
    }
    read_unlock(&tasklist_lock);

    info->num_children = i;
}
```

자식 프로세스 리스트(`tsk->children`)를 순회하려면 `tasklist_lock`을 잡아야 합니다.  
락 없이 순회하면, 순회 도중 자식이 추가/삭제될 때 레이스가 발생할 수 있습니다.

`MAX_CHILDREN`를 넘지 않는 선에서 PID를 배열에 채우고,  
실제 채운 개수는 `num_children` 필드에 저장합니다.

### 부모 PID 채우기

```c
static void fill_parent(struct pid_info *info, struct task_struct *tsk)
{
    struct task_struct *parent;

    rcu_read_lock();
    parent = rcu_dereference(tsk->real_parent);
    if (likely(parent))
        info->parent = parent->pid;
    rcu_read_unlock();
}
```

`real_parent` 필드는 RCU로 보호되는 포인터입니다.  
부모가 동시에 종료될 수 있으므로, RCU read-side critical section 안에서  
`rcu_dereference()`를 통해 안전하게 접근합니다.

### root / pwd 채우기

```c
static void fill_pathname(char *dst, const struct path *path)
{
    char *pathname;
    int len;

    pathname = d_path(path, dst, PATH_MAX);
    if (unlikely(IS_ERR(pathname))) {
        dst[0] = '\0';
        return;
    }

    if (pathname != dst) {
        len = dst + PATH_MAX - 1 - pathname;
        memmove(dst, pathname, len + 1);
    }
}

static void fill_root_and_pwd(struct pid_info *info, struct task_struct *tsk)
{
    struct fs_struct *fs;
    struct path root, pwd;

    task_lock(tsk);
    fs = tsk->fs;

    if (!fs) {
        task_unlock(tsk);
        return;
    }

    get_fs_root(fs, &root);
    get_fs_pwd(fs, &pwd);
    task_unlock(tsk);

    fill_pathname(info->root, &root);
    fill_pathname(info->pwd, &pwd);

    path_put(&root);
    path_put(&pwd);
}
```

- `tsk->fs` 역시 `task_lock`으로 보호되는 필드입니다.  
  락 없이 접근하면 사용 도중 `fs_struct`가 해제될 수 있습니다.
- `get_fs_root()` / `get_fs_pwd()`는 내부에서 seqlock을 사용해 일관성을 보장하고,  
  `path` 객체의 참조 카운트를 증가시킵니다.
- 사용이 끝나면 `path_put()`으로 참조 카운트를 감소시켜야 합니다.
- `d_path()`는 버퍼의 뒤쪽부터 경로 문자열을 채운 뒤,  
  실제 문자열이 시작하는 위치를 가리키는 포인터를 반환합니다.  
  이 포인터는 `dst`와 다를 수 있으므로, `pathname != dst`인 경우  
  문자열 길이를 계산한 뒤 `memmove()`로 버퍼 앞(`dst`)으로 옮깁니다.

### 유저 공간으로 결과 복사

```c
if (copy_to_user(up, info, sizeof(*info)))
    ret = -EFAULT;
```

커널에서 채운 `struct pid_info`를 유저 공간 포인터로 복사합니다.  
`copy_to_user()`가 실패하면 시스템 콜 전체를 실패로 간주하고 `-EFAULT`를 반환합니다.

## 참고 자료
- [Documentation/memory-barriers.txt](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/memory-barriers.txt)
- [Documentation/filesystems/path-lookup.rst](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/filesystems/path-lookup.rst)
- [Documentation/filesystems/path-lookup.txt](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/filesystems/path-lookup.txt)
- [Documentation/RCU/whatisRCU.rst](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/RCU/whatisRCU.rst)
- [An introduction to lockless algorithms](https://lwn.net/Articles/844224/)
- [linux kernel source tree](https://elixir.bootlin.com/linux/v6.18-rc3/source)
