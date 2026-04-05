
# Linux Storage 

```
Disk → Partition → Filesystem → Mount → Use
```

Example:

```
/dev/sdb → /dev/sdb1 → xfs → /mnt/data → files stored
```

## Disk

👉 A disk = storage device

**Examples:**
- /dev/sda → main disk
- /dev/sdb → extra disk

**Check:**
```
lsblk
```

## Partition
A partition = a slice of disk

**Think:**
One disk → divided into parts

**Example:**
- /dev/sdb1
- /dev/sdb2



# Create Partition `fdisk`

#### Using fdisk (most common)
```
sudo fdisk /dev/sdb
```

**Then:**
- n → new partition
- w → save

**After this:**
```
lsblk

```

**You’ll see:**
```
sdb1
```


# Filesystem
Create filesystem
==Without this → disk is unusable==

```
mkfs.xfs /dev/sdb1
```

**or**

```
mkfs.ext4 /dev/sdb1
```


# Mounting (Connecting storage)
Mount = attach storage to directory

#### Manual mount
```
mkdir /mnt/data
mount /dev/sdb1 /mnt/data
```

**Now you can use it:**
```
cd /mnt/data
touch file.txt
```

### Persistent Mount (/etc/fstab)

Manual mount disappears after reboot ❌

#### Permanent mount

**Edit:**
```
nano /etc/fstab
```

**Add:**
```
/dev/sdb1   /mnt/data   xfs   defaults   0 0
```

**Apply:**
```
mount -a
```


# LVM 

**LVM = flexible storage system**

**Instead of fixed partitions:**
```
Disk → PV → VG → LV → Mount
```

| Term | Meaning          |
| ---- | ---------------- |
| PV   | Physical disk    |
| VG   | Pool of storage  |
| LV   | Usable partition |

### Basic LVM Steps
##### 1. Create PV
```
pvcreate /dev/sdb
```

#### 2. Create VG
```
vgcreate myvg /dev/sdb
```

#### 3. Create LV
```
lvcreate -L 1G -n mylv myvg
```

#### 4. Format
```
mkfs.xfs /dev/myvg/mylv
```

#### 5. Mount
```
mount /dev/myvg/mylv /mnt/data
```

### Why LVM?
- Easy to extend storage
- Combine multiple disks
- Flexible resizing

### Basic commands
```
lsblk          # view disks
fdisk          # create partition
mkfs.xfs       # create filesystem
mount          # mount disk
df -h          # check usage
free -h        # check memory/swap
```