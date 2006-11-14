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
-- Table structure for table `device_types`
--

DROP TABLE IF EXISTS `device_types`;
CREATE TABLE `device_types` (
  `type_id` char(2) NOT NULL default '',
  `type_name` char(100) NOT NULL default '',
  PRIMARY KEY  (`type_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

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
-- Table structure for table `group_users`
--

DROP TABLE IF EXISTS `group_users`;
CREATE TABLE `group_users` (
  `group_id` int(16) NOT NULL default '0',
  `user_id` char(32) NOT NULL default '',
  PRIMARY KEY  (`group_id`,`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

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
-- Table structure for table `security_groups`
--

DROP TABLE IF EXISTS `security_groups`;
CREATE TABLE `security_groups` (
  `group_id` int(4) NOT NULL auto_increment,
  `group_name` char(100) NOT NULL default '',
  PRIMARY KEY  (`group_id`)
) ENGINE=MyISAM AUTO_INCREMENT=14 DEFAULT CHARSET=latin1;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2006-11-06 20:47:29
