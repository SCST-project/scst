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


Software Components
-------------------

The following software components are needed by the code in scst_dlm.c:
* The DLM kernel driver (dlm.ko). This driver is only built if CONFIG_DLM
  has been set.
* The DLM control daemon (dlm_controld.pcmk). This daemon passes cluster
  node IDs and IP addresses to the DLM kernel driver via the configfs
  interface of the DLM kernel driver.
* Corosync to manage cluster membership of the cluster nodes and to assign
  a node ID to each cluster node.
* A facility to start the DLM control daemon, e.g. Pacemaker.

On most Linux distributions the software packages that contain this software
have the names kernel, dlm, corosync and pacemaker.

NOTE! You might need to apply a DLM bugfix patch, see scst-devel mailing list
thread https://sourceforge.net/p/scst/mailman/scst-devel/thread/CADHfD59FK6seaammL8b9LM3U3tw5HvYp3kPTk_r1OYkPR7bPhg@mail.gmail.com/#msg34761854
for more details.


DLM Configuration
-----------------

The DLM kernel module supports the TCP and SCTP communication protocols. An
advantage of SCTP for H.A. purposes is that it supports multihoming. One of
these protocols can be selected via the -r <proto> option of dlm_controld.
That option can be set via the "args" argument of the Pacemaker dlm_controld
resource. For more information, see also:
* The dlm_controld(8) man page.
* In the "Pacemaker 1.1, Clusters from Scratch" guide, the section "Configure
  the Cluster for the DLM".
* The dlm_controld resource agent: /usr/lib/ocf/resource.d/pacemaker/controld

Here is an example of how to set up a cluster with two nodes and how to
configure and start the DLM control daemon:
 1. If a network switch is present between the two nodes, enable IPv4 multicast
    on that switch.
 2. Copy /etc/corosync/corosync.conf.example into /etc/corosync/corosync.conf
    and edit that file.
 3. If a file /etc/default/corosync exists, enable Corosync in that file.
 4. Start Corosync:
      systemctl start corosync || /etc/init.d/corosync start
 5. Check that all configured Corosync rings have two members:
      corosync-cfgtool -s && { corosync-cmapctl | grep members; }
 6. Start pcsd:
      systemctl start pcsd || /etc/init.d/pcsd start
 7. Set up cluster authentication:
      pcs cluster auth centos7-vm centos7b-vm
 8. Start Pacemaker:
      systemctl start pacemaker || /etc/init.d/pacemaker start
 9. If the cluster has only two nodes, disable the Pacemaker quorum policy and
    disable STONITH:
      crm_attribute -t crm_config -n no-quorum-policy -v ignore
      crm_attribute -t crm_config -n stonith-enabled -v false
10. Check the cluster status:
      pcs status
11. Create a Pacemaker resource for dlm_controld:
      pcs resource delete dlm
      pcs resource create dlm ocf:pacemaker:controld \
        args="-q0 -f0" allow_stonith_disabled=true \
        op monitor timeout=60 \
	--clone interleave=true
12. Check the Pacemaker status:
      pcs status


Startup and Shutdown
--------------------

The startup sequence is as follows:
* Load and configure SCST with cluster_mode = 0 and with all target ports
  disabled.
* Enable cluster mode for all SCST devices that can be accessed through more
  than one cluster node:
    for x in /sys/kernel/scst_tgt/handlers/*/*/; do
        echo 1 >$x/cluster_mode &
    done
    wait
* Start Corosync and Pacemaker.
* Wait until Pacemaker has reached the idle state:
    pacemaker_dc_status() {
	local dc

	dc="$(crmadmin -D 2>/dev/null | sed 's/Designated Controller is: //')"
	[ -n "$dc" ] &&
	crmadmin -S "$dc" 2>/dev/null |
	sed 's/^Status of crmd@[^[:blank:]]*:[[:blank:]]\([^[:blank:]]*\).*/\1/'
    }
    for ((i=0;i<300;i++)); do
	[ "$(pacemaker_dc_status)" = "S_IDLE" ] && break
	sleep 1
    done
* Enable SCST target ports.
* If no DLM resource has been configured in Pacemaker, start dlm_controld.pcmk
  explicitly.

The proper shutdown order is as follows:
* Tell SCST to stop accepting SCSI commands and wait until all initiators have
  logged out:
    for x in $(find /sys/kernel/scst_tgt/targets/ -name enabled); do
        echo 0 > $x &
    done
    wait
    while ls -Ad /sys/kernel/scst_tgt/targets/*/*/sessions/* >/dev/null 2>&1; do
        sleep 1
    done
* Tell SCST to release the DLM lockspaces:
    while grep -q '^1$' /sys/kernel/scst_tgt/devices/*/cluster_mode 2>/dev/null
    do
        for x in /sys/kernel/scst_tgt/devices/*/cluster_mode; do
            { [ -e "$x" ] && echo 0 > "$x"; } &
        done
        wait
        sleep 1
    done
* Stop Pacemaker and Corosync
* Unload the SCST kernel modules
* Unload the DLM kernel driver


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

 * On APTL bit set, put the PR info on storage on the passive node.


See also
--------

* Bart Van Assche, Using the DLM as a distributed in-memory database, Linux
  Plumbers North America, Seattle, August 20, 2015
  (https://linuxplumbersconf.org/2015/ocw//system/presentations/2691/original/Using%20the%20DLM%20as%20a%20Distributed%20In-Memory%20Database.pdf).
* Andrew Beekhof, Pacemaker Configuration Explained, 2015
  (http://clusterlabs.org/doc/en-US/Pacemaker/1.1/html/Pacemaker_Explained/).
* Andrew Beekhof, Clusters from Scratch, 2015
  (http://clusterlabs.org/doc/en-US/Pacemaker/1.1-pcs/html/Clusters_from_Scratch/index.html).
