---
layout: post
title:  "Escaping Parallels Desktop with Plist Injection"
date:   2023-05-08 00:00:00 +0000
tags: parallels
---

This post details two bugs I found, a plist injection (CVE-2023-27328) and a race condition (CVE-2023-27327), which could be used to escape from a guest Parallels Desktop virtual machine. In this post I'll break down the findings.

For anyone not familiar, [Parallels Desktop](https://www.parallels.com/products/desktop/){:target="_blank"} offers virtualization on macOS. It allows you to run virtual machines, like Windows or Linux, on a macOS host.

## Toolgate & Parallels Tools
Toolgate is the protocol used for communication between the guest and host in Parallels, and it's a great place to start looking for bugs due to its large attack surface and relatively immature security posture. 

On x86 guests (which I'll be using as an example for this blog post) Toolgate requests are sent to the host from the guest by writing the physical address of a `TG_REQUEST` struct to a specific I/O port.

A request structure consists of an opcode (`Request`), a status field (`Status`) which is updated by the host to indicate the status of a request, optional inline data (if `InlineByteCount` > 0), and an optional list of `TG_BUFFER` structs (if `BufferCount` > 0). 
```c
typedef struct _TG_REQUEST {
  unsigned Request;               // opcode
  unsigned Status;                // request status
  unsigned short InlineByteCount; // number of inline bytes
  unsigned short BufferCount;     // number of buffers
  unsigned Reserved;              // reserved
  /* [ inline bytes ] */
  /* [  TG_BUFFERs  ] */
} TG_REQUEST;
```

Parallels Tools is software which can be installed in a guest (similar to VirtualBox Guest Additions, or VMWare Tools) which adds various useful features, such as shared folders, shared clipboard, and drag-and-drop in/out of the VM.

Parallels Tools also adds a channel for userland processes to make Toolgate requests. On Linux this is a proc entry created at `/proc/driver/prl_tg`, which is created and managed by the `prl_tg` kernel module, and on Windows this is a named pipe at `\\.\pipe\parallels_tools_pipe`. Parallels Tools also contains various userland processes and services which use this channel to facilitate these useful features.

Importantly there is a restriction on what Toolgate messages userland processes can send to the host using the channel created by Parallels Tools, which is enforced by the `prl_tg` kernel module. Specifically, the opcode (aka the `Request` field) must be greater than the value of `TG_REQUEST_SECURED_MAX`, which is defined as `0x7fff`, otherwise the write to the proc entry will fail with `EINVAL`. We can see the code for this here:
```c
	/* read request header from userspace */
	if (copy_from_user(src, ureq, sizeof(TG_REQUEST)))
		return -EFAULT;

	/*
	 * requests up to TG_REQUEST_SECURED_MAX are for drivers only and are
	 * denied by guest driver if come from user space to maintain guest
	 * kernel integrity (prevent malicious code from sending FS requests)
	 * dynamically assigned requests start from TG_REQUEST_MIN_DYNAMIC
	 */
	if (src->Request <= TG_REQUEST_SECURED_MAX)
		return -EINVAL;
```

As suggested by the comment, the only Toolgate opcodes which are less than this threshold are those which handle filesystem operations. This means that if we want to send filesystem-related Toolgate requests, we have to bypass this check. More on this later.

## Shared Applications
Shared Applications is a Parallels feature which allows opening files on a Mac in a guest application, and vice versa. It also allows associating file extensions and URL schemes with guest applications. You can read more about this in the [documentation](https://download.parallels.com/desktop/v18/docs/en_US/Parallels%20Desktop%20User's%20Guide/33332.htm).

This feature includes the display of an application's icon in the Mac dock when it's launched within a guest. Here's an example of what it looks like when Microsoft Edge is opened in a Windows guest. We can see that the Edge icon shows up in the dock:
![animation showing Edge appearing in Mac dock when started in a VM](/assets/parallels-plist-escape/sga_mac_dock.gif)

Parallels handles the "syncing" of running guest apps to the host by monitoring for new applications launched in the guest, and then sending Toolgate requests to the host when a new application has started. The host handles these messages by creating and starting "helper" apps, which have the same name and icon as the app in the guest. These helper apps are then displayed in the Mac dock when they are running, and can be used to launch the respective application in the guest from the dock or Launchpad when they are not running. 

This syncing process effectively works like this:
1. Parallels Tools detects an application is launched in the guest
2. It sends a Toolgate request (`TG_REQUEST_FAVRUNAPPS`, opcode `0x8302`) to the host notifying it that an application has launched with a given name and icon
3. If a helper app already exists for this guest app, then that helper app is launched and we're done
4. If the helper app doesn't exist, a new app bundle is created in `~/Applications (Parallels)/<vm_uuid> Applications.localized/`
5. The app bundle is created from a template, which is filled in using information supplied by the guest. The information sent from the guest, as part of the Toolgate request, includes the app name, description and icon, amongst other things. This information is written into several files in the new app bundle, including the [Info.plist](https://developer.apple.com/documentation/bundleresources/information_property_list), which is the (XML) file in an app bundle which includes metadata about the bundle
6. The new helper app is launched, so it shows up in the dock

The helper app contains a binary called `WinAppHelper`, which is copied directly from the template and exists as the entry point for the app bundle. When the app is run this binary will parse the Parallels-specific configuration files in the app bundle (e.g. `AppParams.pva`) and send a message to the corresponding guest VM to start the relevant application, if it's not already running.

Here you can see a snippet of the Info.plist template, which is taken from the hypervisor binary. The highlighted placeholders are replaced with guest supplied input.
![Plist template](/assets/parallels-plist-escape/plist_template.png)

Given that the host is taking input from the guest and using it to fill an Info.plist template, it is important that all input from the guest is appropriately escaped or sanitized, so it is not possible to inject XML into the plist and modify the behaviour of the helper app. I found that the escaping _was_ done for all of the fields provided by the guest, apart from two, the URL schemes and the file extensions. These allow registering file extensions and URL schemes which the guest app will handle, respectively.

This means we could send our own Toolgate request (opcode `0x8302`), to tell the host to create a helper app, with a malicious URL scheme or file extension. In my case I chose to exploit the URL schemes, which were written unescaped into the `CFBundleURLSchemes` array, in Info.plist.

The relevant template for creating the `CFBundleURLSchemes` array looks like this:
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>Supported protocols</string>
    <key>CFBundleURLSchemes</key>
    <array>
    %1
    </array>
  </dict>
</array>
```

The `%1` is replaced with the guest-provided URL schemes, each wrapped in `<string></string>` tags. The completed template is then inserted into the Info.plist template later on.

This is what it looks like in code form: 
![URL scheme template](/assets/parallels-plist-escape/url_schemes_template.png)

One way this can be abused is by using the [LSEnvironment](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html#//apple_ref/doc/uid/20001431-106825) key to set the `DYLD_INSERT_LIBRARIES` environment variable. This can be used to force the helper binary (WinAppHelper) to load an arbitrary dylib when executed. I did spend a while looking for other features of an Info.plist which I could exploit without requiring a second bug, but I wasn't able to find anything better. I'd be very keen to hear any alternative ideas for exploitation.

For example, if we provide the following string as a URL scheme:
```xml
      evil</string>
    </array>
  </dict>
</array>
<key>LSEnvironment</key>
<dict>
  <key>DYLD_INSERT_LIBRARIES</key>
  <string>/path/to/malicious.dylib</string>
</dict>
<key>blabla</key>
<array>
  <dict>
    <key></key>
      <array>
        <string>
```

This gets wrapped in \<string\> tags and inserted into the template, resulting in something like this:
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key>
    <string>Supported protocols</string>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>evil</string>
    </array>
  </dict>
</array>
<key>LSEnvironment</key>
<dict>
  <key>DYLD_INSERT_LIBRARIES</key>
  <string>/path/to/malicious.dylib</string>
</dict>
<key>blabla</key>
<array>
  <dict>
    <key></key>
    <array>
      <string>
    </array>
  </dict>
</array>
```

Now when WinAppHelper is executed it will load a dylib of our choice. If we can make use of an existing dylib which does something interesting, or create our own dylib on disk somewhere, then we can use this to get code execution on the host.

## Getting a File Write
To complete the goal of code execution on the host with no user interaction, I needed to find a way to write a controlled dylib to a known location on the host. Unfortunately there were no files in the helper app bundle which I controlled in their entirety (including e.g. the app icon). Shared folders seemed like a good place to look for bugs which could allow us to do this.

Shared folders in Parallels are actually implemented using Toolgate, which has opcodes for all aspects of file management, including opening, reading and writing files. The shared folder filesystem kernel module (`prl_fs`), writes the relevant Toolgate instructions to the host when filesystem operations occur in the guest, and the host then performs the requested operation.

As mentioned earlier, all of these opcodes are forbidden by the communication channel created by Parallels Tools, which means to send filesystem-related opcodes we need to load our own kernel module to do this, which unfortunately requires root permissions. To do this I took the existing `prl_tg` code and made some modifications to remove the security checks.

Once we can write arbitrary messages to Toolgate, we can open files in a shared folder using the `TG_REQUEST_FS_L_OPEN` (`0x223`) opcode. In the hypervisor, file paths are constructed by appending the file path provided by the guest to the configured shared folder path on the host. There are some security checks when handling an open request to make sure the guest can't open files outside of the host shared folder path, including:
- Checking if the file path contains `..`, which should have already been canonicalized by the guest
- Checking if the file is a symlink which points outside of the share
- Opening the constructed path and checking if the resulting file is outside of the shared folder on the host, which is done using the `F_GETPATH` option of `fcntl`. 

If any of these checks fail then Parallels will refuse to open the file and will return an error to the guest. The checks themselves look good, but the issue was a time-of-check to time-of-use (TOCTOU) opportunity between when the security checks happened and when the file was actually opened. This meant that if we quickly switched the path from a normal file to a symlink pointing to a path outside of the share on the host, after the security checks, but before the open, then the hypervisor would open the target of the symlink on the host for us. After that we could simply read from or write to the opened file using subsequent calls to Toolgate. In other words, this gives us the ability to read or write any file on the host, assuming the host process has permissions.

![animation showing how to exploit the TOCTOU with a symlink](/assets/parallels-plist-escape/toctou.gif)


Ok, but why do we need Toolgate requests for this, if the shared folders filesystem does it for us? In theory this bug _should_ be exploitable by just performing the race with files in a shared folder, without sending manual Toolgate requests. However, in practice, trying to exploit this race through only filesystem operations triggers a bug in the `prl_fs` kernel module which results in a kernel oops.


## Combining the two
The first bug allows us to load any dylib on the host, and the second bug gives us the ability to write an arbitrary file anywhere on the host filesystem (assuming the Parallels process has permissions). Therefore we can create a malicious dylib, write it to a known location on the host, and force a helper app to load it, which will give us code execution with no user interaction.

We can use the following code compiled into a dylib, which will pop a calculator when the dylib is loaded.
```c
#include <stdlib.h>

void __attribute__ ((constructor)) pwn() {
    unsetenv("DYLD_INSERT_LIBRARIES");
    system("osascript -e 'tell application \"Calculator.app\" to activate'");
}
```

## Exploit Demonstration
<video width="100%" controls autoplay playsinline loop>
  <source src="/assets/parallels-plist-escape/full_chain.mp4" type="video/mp4">
</video>

## Conclusion
This chain can be exploited from within any guest operating system by any code with elevated privileges, which are necessary to use the privileged instructions needed to write arbitrary Toolgate requests. If Parallels Tools is installed, then the plist injection bug can be exploited with low privileges, but the file write bug still requires loading our own kernel module to bypass the security restrictions and send our own filesystem-related Toolgate requests.

Overall, Parallels is a fun target. Based on the bugs I and others have found I would say that it's more immature than the likes of VirtualBox and VMWare, and I'm sure there are plenty more bugs to be found here.

<!-- You can find the code for these exploits [on my GitHub](https://github.com/kn32){:target="_blank"}. -->
## Timeline
- Plist injection
  - Assigned CVE-2023-27328 / [ZDI-23-220](https://www.zerodayinitiative.com/advisories/ZDI-23-220/)
  - **2022-11-03** - reported to vendor
  - **2022-12-13** - fix released in version 18.1.1
  - **2023-03-07** - public release of advisory
- File open TOCTOU
  - Assigned CVE-2023-27327 / [ZDI-23-215](https://www.zerodayinitiative.com/advisories/ZDI-23-215/)
  - **2022-11-03** - reported to vendor
  - **2022-12-13** - fix released in version 18.1.1
  - **2023-03-07** - public release of advisory
