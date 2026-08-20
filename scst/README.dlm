Synchronization of the Persistent Reservation Information via the DLM
=====================================================================

Introduction
------------

In an H.A. setup where multiple servers share data it is required that
the persistent reservation state is kept consistent across the cluster.
One possible approach is to use the DLM to keep the PR state synchronized
across nodes. Since the DLM can associate data with each DLM lock object,
DLM lock objects can be used to store PR data. The data that is associated
with a DLM lock object is called the Lock Value Block or LVB. The code in
scst_dlm.c uses the DLM to keep PR data synchronized across all nodes in
a cluster.


Dependencies and deployment
---------------------------

The SCST DLM integration requires a kernel built with DLM support and a
working DLM userspace and cluster-membership stack. SCST consumes the DLM
interfaces; it does not configure membership, quorum or fencing. Follow the
documentation shipped with the selected distribution and cluster stack for
those parts of the deployment.

Do not disable quorum handling or fencing merely to bring up an example.
Incorrect membership or failed-node exclusion can allow multiple nodes to
write shared storage without the required coordination and can corrupt data.
Validate fencing and recovery on a disposable cluster before exporting real
storage.

Every node that accesses the same logical device must use the same stable
t10_dev_id. Enabling cluster_mode selects DLM-backed persistent-reservation
handling and may create or join the lockspace derived from that identifier.


Startup and shutdown ordering
-----------------------------

Use the following ordering as an integration constraint, not as a deployment
script:
* Configure and validate cluster membership, quorum, fencing and DLM according
  to the current cluster-stack documentation.
* Configure SCST while its target ports remain disabled.
* Enable cluster_mode only for shared devices and verify that every node uses
  the same t10_dev_id before enabling target ports.
* During shutdown, disable target ports and wait for initiator sessions and
  commands to drain before disabling cluster_mode.
* Stop the DLM and cluster stack only after SCST has released its lockspaces.

Loading modules, writing cluster_mode, enabling targets and exercising failover
all change live storage or cluster state. Perform them only with an explicit
host, device, fencing and recovery plan.


Lockspace names
---------------

The names of the DLM lockspaces used by SCST follow the following pattern:
scst-<t10_dev_id> where t10_dev_id is the T10 device ID of the SCST device
associated with this lockspace.


Notes
-----

Since the lockspace name depends on the t10_dev_id it is not allowed to
change the t10_dev_id if cluster mode has been enabled.


Testing
-------

Two examples of test suites for the cluster PR support code are:
* The SCSI conformance tests in the libiscsi project.
* The Windows Cluster Validation Tests
  (https://technet.microsoft.com/en-us/library/Cc726064.aspx).


To do
-----

 * Ensure that PREEMPT AND ABORT affects all cluster nodes instead of
   only the cluster node that received this command.


See also
--------

* Bart Van Assche, Using the DLM as a distributed in-memory database, Linux
  Plumbers North America, Seattle, August 20, 2015
  (https://linuxplumbersconf.org/2015/ocw//system/presentations/2691/original/Using%20the%20DLM%20as%20a%20Distributed%20In-Memory%20Database.pdf).
* Andrew Beekhof, Pacemaker Configuration Explained, 2015
  (http://clusterlabs.org/doc/en-US/Pacemaker/1.1/html/Pacemaker_Explained/).
* Andrew Beekhof, Clusters from Scratch, 2015
  (http://clusterlabs.org/doc/en-US/Pacemaker/1.1-pcs/html/Clusters_from_Scratch/index.html).
