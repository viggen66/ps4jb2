Enhanced exploit race condition mitigation for original sleirsgoevy ps4jb2.

1) Each critical thread is bound to a specific core 
2) Real-Time scheduling (threads are promoted to maximum priority, to prevent preemption by OS background tasks), enhancing race condition.
3) Malloc spray is performed on all available cores, for increased reclaiming freed memory during UAF and exploit success.
