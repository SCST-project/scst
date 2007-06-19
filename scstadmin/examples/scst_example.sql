-- MySQL dump 10.10
--
-- Host: localhost    Database: scst
-- ------------------------------------------------------
-- Server version	5.0.26-Debian_1-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `assignments`
--

DROP TABLE IF EXISTS `assignments`;
CREATE TABLE `assignments` (
  `device_id` int(8) NOT NULL default '0',
  `type_id` char(2) default NULL,
  `group_id` int(4) NOT NULL default '0',
  `host_id` int(2) NOT NULL default '0',
  `target_id` int(2) NOT NULL default '0',
  `target_lun` int(3) NOT NULL default '0',
  PRIMARY KEY  (`device_id`,`group_id`,`host_id`,`target_id`,`target_lun`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `assignments`
--

LOCK TABLES `assignments` WRITE;
/*!40000 ALTER TABLE `assignments` DISABLE KEYS */;
INSERT INTO `assignments` VALUES (5,'MS',13,0,0,0),(5,'MP',11,0,0,0),(13,'MP',6,0,0,0),(0,'GW',1,0,0,0),(1,'GW',1,0,0,1),(12,'MP',12,0,0,0),(6,'MP',8,0,0,0),(8,'MP',8,0,0,1),(9,'MP',9,0,0,0),(10,'MP',10,0,0,0),(11,'MP',10,0,0,1),(7,'MP',11,0,0,1),(14,'MP',8,0,0,2),(0,'MS',7,0,0,0),(1,'RG',9,0,0,3),(0,'RG',9,0,0,2),(6,'MS',9,0,0,1);
/*!40000 ALTER TABLE `assignments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_types`
--

DROP TABLE IF EXISTS `device_types`;
CREATE TABLE `device_types` (
  `type_id` char(2) NOT NULL default '',
  `type_name` char(100) NOT NULL default '',
  PRIMARY KEY  (`type_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `device_types`
--

LOCK TABLES `device_types` WRITE;
/*!40000 ALTER TABLE `device_types` DISABLE KEYS */;
INSERT INTO `device_types` VALUES ('GW','Gateway Communication Device'),('MP','Mirrored Pair Device'),('SV','Snapshot Device'),('SD','Single Disk Device (Unprotected)'),('SS','Stripe Set (VERY Unprotected)'),('RG','Raid 5 Group Device'),('MS','Mirrored Stripe Device');
/*!40000 ALTER TABLE `device_types` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `devices`
--

DROP TABLE IF EXISTS `devices`;
CREATE TABLE `devices` (
  `device_id` int(8) NOT NULL default '0',
  `type_id` char(2) NOT NULL default '',
  `perf_id` char(3) NOT NULL default '',
  `md_uuid` char(40) default NULL,
  `device_path` char(100) default NULL,
  `options` char(50) default NULL,
  `blocksize` int(6) default NULL,
  `scst_handlr_id` int(2) NOT NULL default '0',
  PRIMARY KEY  (`device_id`,`type_id`)
) ENGINE=MyISAM AUTO_INCREMENT=29 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `devices`
--

LOCK TABLES `devices` WRITE;
/*!40000 ALTER TABLE `devices` DISABLE KEYS */;
INSERT INTO `devices` VALUES (7,'MP','15K','','/dev/evms/MP15K007',NULL,NULL,2),(5,'MP','15K','','/dev/evms/MP15K005',NULL,NULL,2),(6,'MP','15K','','/dev/evms/MP15K006',NULL,NULL,2),(4,'MP','15K','','/dev/evms/MP15K004',NULL,NULL,2),(8,'MP','15K','','/dev/evms/MP15K008',NULL,NULL,2),(9,'MP','15K','','/dev/evms/MP15K009',NULL,NULL,2),(10,'MP','15K','','/dev/evms/MP15K00a',NULL,NULL,2),(11,'MP','15K','','/dev/evms/MP15K00b',NULL,NULL,2),(12,'MP','15K','','/dev/evms/MP15K00c',NULL,NULL,2),(0,'GW','15K','','/dev/evms/GW15K000',NULL,NULL,2),(1,'GW','15K','','/dev/evms/GW15K001',NULL,NULL,2),(13,'MP','15K','','/dev/evms/MP15K00d',NULL,NULL,2),(14,'MP','15K','','/dev/evms/MP15K00e',NULL,NULL,2),(6,'MS','10K','','/dev/evms/MS10K002',NULL,NULL,2),(5,'MS','15K','','/dev/evms/MS15K003',NULL,NULL,2),(1,'RG','72K','','/dev/evms/RG72K001',NULL,NULL,2),(2,'MS','15K','','/dev/evms/MS15K002',NULL,NULL,2),(1,'MS','15K','','/dev/evms/MS15K001',NULL,NULL,2),(0,'MS','15K','','/dev/evms/MS15K000',NULL,NULL,2),(0,'RG','10K','','/dev/evms/RG10K000',NULL,NULL,2);
/*!40000 ALTER TABLE `devices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `group_users`
--

DROP TABLE IF EXISTS `group_users`;
CREATE TABLE `group_users` (
  `group_id` int(16) NOT NULL default '0',
  `user_id` char(32) NOT NULL default '',
  PRIMARY KEY  (`group_id`,`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `group_users`
--

LOCK TABLES `group_users` WRITE;
/*!40000 ALTER TABLE `group_users` DISABLE KEYS */;
INSERT INTO `group_users` VALUES (6,'20:00:00:e0:8b:03:9e:1a'),(6,'21:00:00:e0:8b:03:9e:1a'),(7,'20:00:00:e0:8b:11:3f:8d'),(7,'21:00:00:e0:8b:11:3f:8d'),(8,'20:00:00:e0:8b:11:06:8a'),(8,'21:00:00:e0:8b:11:06:8a'),(9,'20:00:00:e0:8b:11:8d:8a'),(9,'21:00:00:e0:8b:11:8d:8a'),(10,'20:00:00:e0:8b:11:75:8b'),(10,'21:00:00:e0:8b:11:75:8b'),(11,'20:00:00:e0:8b:11:a6:8b'),(11,'21:00:00:e0:8b:11:a6:8b'),(12,'20:00:00:e0:8b:13:ba:01'),(12,'21:00:00:e0:8b:13:ba:01'),(13,'20:00:00:e0:8b:03:d8:4a'),(13,'21:00:00:e0:8b:03:d8:4a');
/*!40000 ALTER TABLE `group_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `perf_types`
--

DROP TABLE IF EXISTS `perf_types`;
CREATE TABLE `perf_types` (
  `perf_id` char(3) NOT NULL default '',
  `perf_name` char(100) NOT NULL default '',
  PRIMARY KEY  (`perf_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `perf_types`
--

LOCK TABLES `perf_types` WRITE;
/*!40000 ALTER TABLE `perf_types` DISABLE KEYS */;
INSERT INTO `perf_types` VALUES ('15K','15K RPM UltraSCSI-2'),('10F','10K RPM Fibre'),('72I','7200 RPM ATA/SATA'),('54I','5400 RPM ATA/SATA'),('10I','10K RPM ATA/SATA');
/*!40000 ALTER TABLE `perf_types` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scst_handlers`
--

DROP TABLE IF EXISTS `scst_handlers`;
CREATE TABLE `scst_handlers` (
  `scst_handlr_id` int(2) NOT NULL default '0',
  `handler_name` char(32) NOT NULL default '',
  `autoload` enum('N','Y') NOT NULL default 'N',
  PRIMARY KEY  (`scst_handlr_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `scst_handlers`
--

LOCK TABLES `scst_handlers` WRITE;
/*!40000 ALTER TABLE `scst_handlers` DISABLE KEYS */;
INSERT INTO `scst_handlers` VALUES (1,'disk','N'),(2,'vdisk','Y'),(3,'cdrom','N'),(4,'changer','N'),(5,'disk_perf','N'),(6,'modisk','N'),(7,'modisk_perf','N'),(8,'tape','N'),(9,'tape_perf','N');
/*!40000 ALTER TABLE `scst_handlers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `security_groups`
--

DROP TABLE IF EXISTS `security_groups`;
CREATE TABLE `security_groups` (
  `group_id` int(4) NOT NULL auto_increment,
  `group_name` char(100) NOT NULL default '',
  PRIMARY KEY  (`group_id`)
) ENGINE=MyISAM AUTO_INCREMENT=14 DEFAULT CHARSET=latin1;

--
-- Dumping data for table `security_groups`
--

LOCK TABLES `security_groups` WRITE;
/*!40000 ALTER TABLE `security_groups` DISABLE KEYS */;
INSERT INTO `security_groups` VALUES (1,'Default'),(6,'CORBIN3_a'),(12,'PC3_a'),(7,'PC1_a'),(8,'MENTASM_a'),(9,'CORBIN2_a'),(10,'RAISTLIN_a'),(11,'PC4_a'),(13,'PC2_a');
/*!40000 ALTER TABLE `security_groups` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2006-11-06 20:47:39
