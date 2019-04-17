#  Crypto-IP
Mr.Lee's Crypto-IP(IP anonymous) experiment repository.



* Crypto-PAn.1.0's Readme
  * Introduction

    * 这是由Jun Xu，Jinliang Fan，Mostafa Ammar和Sue Moon撰写的“Prefix-Preserving-Preserving IP Address Anonymization：Measurement-based Security Evaluation and a New Cryptography-based Scheme”中描述的基于加密的前缀保留跟踪匿名化技术的实现。 在这个实现中，我们使用Rijndael密码（AES算法）作为底层伪随机函数。

  * Files

    * rijndael.h rijndael.cpp：Szymon Stefanek（stefanek@tin.it）基于Vincent Rijmen和K.U.Leuven实现2.4的Rijndael密码（现在成为AES）的C ++实现。

      panonymizer.h panonymizer.cpp：我们使用Rijndael密码作为伪随机函数实现保留前缀的IP匿名者。这两个文件实现了类PAnonymizer。类PAnonymizer在用于以前缀保留方式匿名化IP地址之前需要256位密钥进行初始化。

      sample.cpp这是一个示例程序，用于说明类PAnonymizer的使用。程序读入示例跟踪文件“sample_trace_raw.dat”，对跟踪文件中的IP地址进行匿名处理，并将已清理的跟踪文件输出到标准输出。如果您愿意，可以将输出重定向到文件。文件中的密钥是可设置的。

      sample_trace_raw.dat这是一个示例原始跟踪文件。跟踪的每一行的格式为“time packetsize a.b.c.d”，其中“a.b.c.d”是IP地址。已清理的跟踪具有相同的格式，保留除IP地址之外的所有内容，这些IP地址是匿名的。

      sample_trace_anonymized.dat这是在“sample_trace_raw.dat”上运行示例程序时的输出。

  * Complie and run the sample program

    * To compile the sample program "sample.cpp", run "make all"
    * To run the sample program, run "sample sample_trace_raw.dat"
    * 已清理的“sample_trace_raw.dat”版本被写入标准输出。 您可以将输出重定向到文件，并将其与文件“sample_trace_anonymized.dat”进行比较。 它们应该是一样的。

  * Tailor the sample program for your own needs.

    * 要清理自己的跟踪，您需要更改文件“sample.cpp”以反映您的跟踪格式。 在创建类PAnonymizer的实例时，您还需要在程序中提供自己的256位密钥。