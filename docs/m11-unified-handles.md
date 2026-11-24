# M11.4.1 — Task-queue handles share the process handle table

This slice removes the task queue service's independent monotonically
increasing 64-bit handle namespace.

## Representation and ownership

- A task queue is now a `RuntimeObject` with built-in type `TaskQueue`.
- The queue object is registered with the runtime `ObjectManager`.
- The owning process's M4 `HandleTable` issues the guest-visible handle.
- `XTaskQueueDuplicateHandle` creates an independent slot referring to the
  same object. Closing one alias does not invalidate another.
- Handle generation and table identity checks now apply to task queues as
  they already do to events, mutexes, and semaphores.
- Queue callback state remains owned by the queue object and protected by the
  task-queue service lock. Dispatch pins the object while waiting or invoking
  a callback, so final close signals termination before object destruction
  drains active users.

## Current boundary

`XTaskQueueCloseHandle` closes the task-queue type through the task-queue
service. The existing Win32 `CloseHandle` adapter still has its narrower
synchronization-object dispatch and does not yet route TaskQueue handles.
Therefore this is a shared token/object table foundation, not completion of
 the generic type-directed close API.

Automatic/thread-pool dispatch, delayed callbacks, and scheduler-aware
cancellation remain unsupported.
