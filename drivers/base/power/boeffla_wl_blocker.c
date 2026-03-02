/*
 * Author: andip71, 01.09.2017
 * Modified for UI Compatibility: Gemini, 2026
 * Version 1.1.1
 */

#define pr_fmt(fmt) "Boeffla WL blocker: " fmt

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "boeffla_wl_blocker.h"

/*****************************************/
// Variables
/*****************************************/

char list_wl[LENGTH_LIST_WL];
char list_wl_default[LENGTH_LIST_WL_DEFAULT];

extern char list_wl_search[LENGTH_LIST_WL_SEARCH];
extern bool wl_blocker_active;
extern bool wl_blocker_debug;

/*****************************************/
// Internal functions
/*****************************************/

static void build_search_string(const char *list1, const char *list2)
{
    // Utilisation de snprintf pour plus de sécurité (évite buffer overflow)
    snprintf(list_wl_search, LENGTH_LIST_WL_SEARCH, ";%s;%s;", list1, list2);

    if (strlen(list_wl_search) > 5)
        wl_blocker_active = true;
    else
        wl_blocker_active = false;
}

/*****************************************/
// Sysfs interface functions
/*****************************************/

// Show list of user configured wakelocks
static ssize_t wakelock_blocker_show(struct device *dev, struct device_attribute *attr,
                char *buf)
{
    // FIX: Retrait du \n pour que l'app Android reconnaisse la chaîne brute
    return scnprintf(buf, PAGE_SIZE, "%s", list_wl);
}

// Store list of user configured wakelocks
static ssize_t wakelock_blocker_store(struct device * dev, struct device_attribute *attr,
                 const char * buf, size_t n)
{
    size_t count = n;

    if (n >= LENGTH_LIST_WL)
        return -EINVAL;

    // Copie sécurisée du buffer
    memset(list_wl, 0, LENGTH_LIST_WL);
    memcpy(list_wl, buf, n);
    list_wl[n] = '\0';

    // Nettoyage des retours à la ligne (indispensable pour l'UI)
    char *p;
    if ((p = strchr(list_wl, '\n')) != NULL) *p = '\0';
    if ((p = strchr(list_wl, '\r')) != NULL) *p = '\0';

    build_search_string(list_wl_default, list_wl);

    return count;
}

// Show list of default, predefined wakelocks
static ssize_t wakelock_blocker_default_show(struct device *dev, struct device_attribute *attr,
                char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "%s", list_wl_default);
}

// Store list of default, predefined wakelocks
static ssize_t wakelock_blocker_default_store(struct device * dev, struct device_attribute *attr,
                 const char * buf, size_t n)
{
    if (n >= LENGTH_LIST_WL_DEFAULT)
        return -EINVAL;

    memset(list_wl_default, 0, LENGTH_LIST_WL_DEFAULT);
    memcpy(list_wl_default, buf, n);
    list_wl_default[n] = '\0';

    char *p;
    if ((p = strchr(list_wl_default, '\n')) != NULL) *p = '\0';

    build_search_string(list_wl_default, list_wl);

    return n;
}

// Show debug information
static ssize_t debug_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE,
             "Debug: %d\nUser: %s\nDefault: %s\nSearch: %s\nActive: %d\n",
             wl_blocker_debug, list_wl, list_wl_default,
             list_wl_search, wl_blocker_active);
}

static ssize_t version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    // FIX: Version pure sans \n pour le handshake de l'app
    return scnprintf(buf, PAGE_SIZE, "%s", BOEFFLA_WL_BLOCKER_VERSION);
}

/*****************************************/
// Initialize sysfs objects
/*****************************************/

static DEVICE_ATTR_RW(wakelock_blocker);
static DEVICE_ATTR_RW(wakelock_blocker_default);
static DEVICE_ATTR_RO(version);

static struct dev_ext_attribute dev_attr_debug = {
    __ATTR(debug, 0644, debug_show, device_store_bool),
    &wl_blocker_debug
};

static struct attribute *boeffla_wl_blocker_attributes[] = {
    &dev_attr_wakelock_blocker.attr,
    &dev_attr_wakelock_blocker_default.attr,
    &dev_attr_debug.attr.attr,
    &dev_attr_version.attr,
    NULL
};

static struct attribute_group boeffla_wl_blocker_control_group = {
    .attrs = boeffla_wl_blocker_attributes,
};

static struct miscdevice boeffla_wl_blocker_control_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "boeffla_wakelock_blocker",
};

/*****************************************/
// Driver init and exit functions
/*****************************************/

static int __init boeffla_wl_blocker_init(void)
{
    int err = 0;

    err = misc_register(&boeffla_wl_blocker_control_device);
    if (err) {
        pr_err("failed register the device.\n");
        return err;
    }

    err = sysfs_create_group(&boeffla_wl_blocker_control_device.this_device->kobj,
                 &boeffla_wl_blocker_control_group);
    if (err) {
        pr_err("failed to create sys fs object.\n");
        misc_deregister(&boeffla_wl_blocker_control_device);
        return err;
    }

    // Initialisation sécurisée des listes
    memset(list_wl, 0, LENGTH_LIST_WL);
    strncpy(list_wl_default, LIST_WL_DEFAULT, LENGTH_LIST_WL_DEFAULT - 1);
    
    build_search_string(list_wl_default, list_wl);

    pr_info("driver version %s started\n", BOEFFLA_WL_BLOCKER_VERSION);
    return 0;
}

static void __exit boeffla_wl_blocker_exit(void)
{
    sysfs_remove_group(&boeffla_wl_blocker_control_device.this_device->kobj,
                           &boeffla_wl_blocker_control_group);
    misc_deregister(&boeffla_wl_blocker_control_device);
    pr_info("driver stopped\n");
}

module_init(boeffla_wl_blocker_init);
module_exit(boeffla_wl_blocker_exit);

MODULE_AUTHOR("andip71");
MODULE_DESCRIPTION("Boeffla Wakelock Blocker");
MODULE_LICENSE("GPL v2");
