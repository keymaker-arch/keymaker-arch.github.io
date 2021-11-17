# Snort

## 1. Snort Rules

Snort rules are divided into two logical sections, the rule header and the rule options. The rule header contains the rule's action, protocol, source and destination IP addresses and netmasks, and the source and destination ports information. The rule option section contains alert messages and information on which parts of the packet should be inspected to determine if the rule action should be taken.

```
[action] [source_ip] [source_port] [direction] [target_ip] [target_port] ([rule])
```



e.g.

```
alert any any -> any any (content:"|A1 B0 6F 3D|";msg:"detected";sid=1000001;rec:1;)
```



## 2.reference

1. https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/249/original/snort_manual.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMGOEV4EFM%2F20211113%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211113T034836Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=812c8bb68bf77fe475e6aa47bcd508924fe1f13ec3d8beaefa977761f45ee8ed

