#介绍
---
近几年来，客户端应用程序关于传输动态，定制内容的驱动力有了显著上升。从以往来说，这种内容加载的方式已经可以通过布局指令和脚本功能相结合的模式来实现了。这种模式可以通过编程的方式修改规范数据格式，修改布局（例如html和javascript）。这种模式现在发展到可以通过在嵌入对象，扩展布局属性和脚本引擎之间的协作完成更加精细的操作。这种新的互操作性促进了跨技术和平台的无缝对接的用户体验的建立。
本文旨在讨论软件互操作性层面的安全隐患，尤其关注几种突出的Web浏览器技术。我们将在文中揭示大量由允许互操作性而导致的攻击面，并讨论存在其中的几种独特类型的漏洞。灵台，我们将探讨互操作特性在主机应用程序的实现对系统安全性的影响，具体来说，我们将演示由于信任某些可插拔组件而导致的系统安全功能的破坏。虽然本文主要关注目前Web浏览器中存在的几个存在互操作性的层面，但是很多漏洞和审计策略的讨论同样适用于可以执行组件之间数据交换的软件之中。这类软件通常包括脚本语言，插件结构，RPC堆栈和虚拟机等。
##本文组织结构
本文主要分为三个部分。首先在第一个部分，我们将对各种攻击面有一个简单的介绍。具体来说，就是梳理通用的浏览器体系结构，并重点介绍与攻击互操作性层面相关的组件；第二部分将对两个流行的浏览器（Microsoft Internet Explorer（IE）和Mozilla Firefox）中攻击互操作性组件的技术细节进行剖析；第三节将列举在已经识别的攻击面中出现的漏洞类型，并提供发现此类问题的实用方法；最后，本文将对作者发现的一些实际存在的关键漏洞进行讨论。

#第一节	攻击面
---
在深入讨论目标的软件层面之前，从概念层面了解攻击面是非常重要的。图1显示了当代Web浏览器的高级架构图，在图中我们看到的是与本文相关的部分组件。

<center>![image](https://github.com/rofmia/Attack-Interoperability_Translation/tree/master/Images\1.png)</center>
<font color='#0000dd'><center>图1	Web浏览器高级架构图</center></font>

我们可以看到，图1分为三个逻辑层次。第一层，是浏览器核心，该层次包括为插件与浏览器提供交互环境的几个组件。这些插件主要是通过脚本来控制的，但是在某些情况下，它们也可以直接与浏览器的文档对象模型（DOM）进行交互。
第二层是插件本身。插件本质上就是浏览器加载的对象，它们通过处理特定的文档类型来实现其他的功能。浏览器可以很明确的通过策略配置选择信任或者拒绝插件运行，但是它们有时可能会在浏览器的单独进程中运行。。例如IE8浏览器在Windows vista 或者win7系统上运行时，会在限制较多的“低完整性”上下文中运行，部分插件则会在限制较少的“中等完整性”上下文中运行，导致多个插件运行时会耗尽进程资源。这个策略会允许插件在浏览器中得到完全信任，而操作系统上下文中配置得到较低的信任。
最后，第三层是隐式授信对象，及受信任的插件可以加载以便于扩展自身功能的对象。由于浏览器显式地将插件（插件X）作为授信对象，且插件X的授信级别会扩展到任意对象（对象Y），所以我们说，浏览器和授信插件加载的任意对象之间存在可传递的信任关系（B - > X，X - > Y，因此B - > Y）。我们将在文章的第二部分用实例说明：扩展程序的信任传递关系可以允许攻击者利用插件及其可信组件破坏浏览器的安全模型。第三层中另一个需要注意的部分是：在很多情况下，一些浏览器插件会通过自定义功能的脚本与浏览器提供的脚本引擎或DOM进行交互。事实上，这种情况在很多流行插件中都有法身个，比如Adobe Flash，Sun Java和Mircosoft Silverlight等。在这些情景之下，授信关系由软件隐式调用的插件中传递出来，这就允许攻击者利用这样的信任关系获许使用脚本语言所能完成的所有功能。此外，攻击者还可以从脚本语言中将精心构造的对象注入到浏览器进程上下文中，由于信任传递性的关系，这些对象就可能被脚本引擎之外的DOM或者其他插件操纵，有时候会产生意想不到的后果。
信任扩展并不是互操作特性唯一的安全代价。从图1可以看出，为了使每个附加的组件相互交互，互操作的组件之间必须建立通信桥（由图1的双向箭头表示）。这些通信桥本身就是一个相当大的攻击面：通信桥的功能是负责将数据从一个组件编组导出到另一个组件，而编组的过程协作组件对本地组件数据结构隐式的转换。这一操作过程在某种程度上是静默执行的，所以在尝试发现漏洞时，这一过程往往会被忽略。实际上，目前在针对浏览器插件对象的安全评估上已经由大量可检索的资料了，但是很少出现关于检查互操作性的信息。本文恰恰是想要改善对这一角度缺乏审查的现状。
互操作性是各种独特漏洞发育的温床，这类漏洞此前并未被大量的挖掘出来（文章时间2009年，译者注）。由于这些操作，数据结构编组的基础框架往往会导致类型混淆（由于类型误解而导致数据误用）和对象保留（虚假引用计数问题）相关的漏洞，这类问题在其他领域往往是很少见的。虽然这类漏洞此前只是偶尔被发掘出来，但是我们要向大家展示目标软件中流行的API是如何容易受到攻击，同时我们也会在第二部分提供发掘这类漏洞的策略。我们应该注意的是，尽管本文中提到的体系结构是以Web浏览器为中心，但是这类问题在任何软件中都是系统性的，因为很多软件都会为不同组件处理数据提供内部协作的平台。
#第二节	技术概述
---
为了说明本文提出的“攻击互操作性”的概念，本节将提供部分相关技术研究的案例作为说明。本节的案例包括Internet Explorer中的ActiveX控件架构，以及Mozilla的NPAPI插件架构（主要存在于Firefox, Google Chrome及其他一些非浏览器应用程序中）。这一节中我们将探讨如何在可用的通用脚本语言中表示对象，如何将他们编组并导出到插件入口点，以及如何进行DOM交互。最后我们将提供ActiveX和NPAPI的攻击面摘要，总结每种技术在攻击面中所扮演的不同角色。

##MircoSoft ActiveX

ActiveX是一种源于微软COM技术的技术。它用于创建可以暴露给Runtime引擎（例如JavaScript和VBScript）的插件，以便于为宿主应用程序提供额外的功能。为了在第三节中更好地探讨这些漏洞，我们需要深入了解关于COM/Automation架构的知识内容。因此，我们在本节中讨论相关的技术。另外，我们还将探讨“持久化对象”的概念，它是序列化的COM对象，可以嵌入到网页当中。第三节，我们将介绍关于利用持久COM对象作用于COM编组组件中的漏洞，同时破坏浏览器安全功能的方法。
###插件注册

ActiveX空间是COM对象的特例，因此在系统注册表中会有一个描述实例化信息的表项。与其他所有的COM对象一样，每个ActiveX对象都会有一个唯一个Class ID （CLSID）标识，键值信息位于HKEY_CLASSES_ROOT\CLSID\{<CLSID>}这个表项中。此外，HKEY_CURRENT_USER这个表项也可以用于存储针对每个用户安装的对象。由于COM对象在Windows操作系统中非常广泛的使用，IE浏览器需要通过一种机制去限制Web浏览器允许启动哪些COM对象。随着时间的推移，安全机制的定义变得更加细化，这里将进行简要叙述。
####ActiveX插件：安全控件
IE浏览器有几种确定ActiveX对象是否具有执行权限的机制。控件的安全权限分为两类：初始化和脚本。初始化安全指的是是否允许来自持久COM流中的数据来进行控件的实例化（稍后将深入讨论）；脚本安全指的是是否可以通过运行时公开的脚本API来对控件进行操作。有关ActiveX安全控件的完整描述，请访问Microsoft网址http://msdn.microsoft.com/en-us/library/bb250471(VS.85).aspx，本节中大部分逆向工程之外的信息内容均来自此网页。
注册控件
将控件标记为脚本（Safe for Scripting，SFS）或安全初始化（Safe for Initialization，SFI）的第一个广为人知的方法是在注册表相应控件表项中添加子键。在Implemented Categories子表项中添加两个值7DD95801-9882-11CF-9FA9-00AA006C42C4 (CATID_SafeForScripting) 和7DD95802-9882-11CF-9FA9-00AA006C42C4 (CATID_SafeForInitialization)即可标记SFS和SFI。图2内容展示了此类控件的示例。
<center>![Image](https://github.com/rofmia/Attack-Interoperability_Translation/tree/master/Images\2.png)</center>
<font color='#0000dd'><center>图2	将ActiveX控件标记为SFS和SFI的方法</center></font>

控件可以使用StdComponentCategoriesMgr对象程序化地注册自身。IcatRegister接口包括RegisterClassImplCategories()方法，该方法可用于处理所有给定COM对象的类别注册信息。所以StdComponentCategoriesMgr使用上述方法更新注册表。
IE浏览器也使用StdComponentCategoriesMgr对象，但是是用于枚举而非注册。IcatInformation结构提供了一个名为IsClassOfCategories()的函数，IE可以通过调用该函数来确定控件是SFS还是SFI，这个函数内部实现即为查询上述注册表项的键值以确定控件的属性信息。http://msdn.microsoft.com/en-us/library/ms692689(VS.85).aspx对组件类别管理的信息进行深度介绍。
IObjectSafety接口
控件标记SFS和SFI存在可替代方法：ActiveX控件可以通过实现IObjectSafety接口为安全限制需求提供支持。使用这种方法时，需要调用IObjectSafety::GetInterfaceSafetyOptions()方法，返回控件的安全性。该方法原型如下：
HRESULT IObjectSafety::GetInterfaceSafetyOptions(
	REFIID riid,
	DWORD *pdwSupportedOptions,
	DWORD *pdwEnabledOptions
);

IE通过调用这个函数来确定支持的安全选项集合，如果接口返回值显示支持安全选项，IE会调用IObjectSafety接口的SetInterfaceSafetyOptions() 方法表明它希望执行对象。该方法的函数原型如下：
HRESULT IObjectSafety::SetInterfaceSafetyOptions(
	REFIID riid, 
	DWORD dwOptionSetMask, 
	DWORD dwEnabledOptions
);

如果GetInterfaceSafetyOptions()方法成功返回，则表明应用程序知道对象符合应用程序对安全选项的要求，可以使用COM对象。这个API在COM类别的附加信息是：控件可提供关于如何使用控件的更细粒度的控制方法，因为它能够根据riid参数中指定的接口ID信息为不同的接口指定不同的安全设置信息。另外，IObjectSafety接口可以执行本地代码以确定创建对象的应用程序是否可以安全地执行该操作。Mircosoft提供的SiteLock模板代码是这类操作方法的一个实例，该模板代码允许程序员将ActiveX控件限制为预设的URL列表。
ActiveX Killbits
IE也通过允许管理员专门禁止某一浏览器中实例化的控件实现了对标准安全功能的覆盖。这种方法是通过HKEY_LOCAL_MACHINE \ Software \ Microsoft \ Internet Explorer \ ActiveX Compatibility注册表项中添加一个子项来实现的。子项中必须有控件的CLSID，并包含一个DWORD值“Compatibility Flags”。这个值被设置为0x400（killbit）。图3即为给控件设置killbit的实例：

图3	killbit设置图
当应用程序想要确定一个控件是否设置killbit时，可以通过调用CompatFlagsFromClsid()函数来实现，这个函数是urlmon.dll的一个导出函数，函数原型如下：
HRESULT CompatFlagsFromClsid(
	CLSID *pclsid, 
	LPDWORD pdwCompatFlags, 
	LPDWORD pdwMiscStatusFlags
);

当应用程序调用此函数时，它将传入目标COM对象的CLSID，以及两个DWORD指针，指针的值会等于函数成功返回时对象的兼容性及其他OLE标志。然后应用程序将判断是否有0x400（killbit）以确定控件是否设置了killbit。
如果设置了killbit，注册表中会出现一个表示备用ClassID的新条目。这个备用ClassID会被用来代替Internet Explorer中原始 Class ID。图4显示了一个使用备用Class ID 的Class ID的注册表项。当处理图4中的控件时，IE会将COM对象的CLSID由{41B23C28-488E-4E5C-ACE2-BB0BBABE99E8} 转化为 {52A2AAAE-085D-4187-97EA-8C30DB990436}.。

图4	带有备用CLSID的COM对象
预批准列表和ActiveX Opt-In
Microsoft在Internet Explorer 7中引入了一项名为ActiveX Opt-In（选择性加入）的功能。该功能旨在通过允许在网页在实例化未加载对象或此前IE为安装的对象之前向用户发起通知来减少浏览器被攻击的可能。图5显示了注册表HKEY_LOCAL_MACHINE \ Software \ Microsoft \ Windows \ CurrentVersion \ Ext \ PreApproved键值的配置信息

图5 系统注册表中预批准列表的键值
Windows系统基本安装中，已经由很多控件加入预批准列表当中。但是更多的安全脚本或初始化控件并没有出现在这个列表当中，该功能为列表中涵盖的控件的漏洞发现提高了可能性。
每个用户ActiveX的安全性
IE8引入了一系列预安全浏览相关的附加安全功能，这些功能包括对ActiveX的一些改进。在添加这些功能之前，可以在每台计算机上配置控制权限。新增的功能将killbit的力度由每台机器细化到每个用户，并通过允许基于用户和域的选择性加入功能扩展ActiveX的opt-in。
传统来说，killbit可以有效地禁止整个控件系统的实例化。在许多用户系统上单个用户需要而其他用户不需要它的情况下，这个模型还是存在问题的。Microsoft通过引入注册表项HKEY_CURRENT_USER \ Software \ Microsoft \ Windows \ CurrentVersion \ Ext \ Settings \ {CLSID}扩展了killbits，其中CLSID是要限制的ActiveX控件的Class ID。将Flag值设为1，则可限制单个用户的控件。具体信息如图6所示：

图6 单个用户控件限制示例
将ActiveX控件限制到某些域的操作方式可以促使用户对ActiveX控件安全性进行更加精细的控制。最初，SiteLock是唯一允许域限制的方法，但是这种方法不能够由终端用户进行配置。 通过向注册表HKEY_CURRENT_USER \ Software \ Microsoft \ Windows \ CurrentVersion \ Ext \ Stats \ {CLSID} \ iexplore \ AllowedDomains，添加特定被允许域用户的秘钥，可以对域进行管理。 通配符“*”表示添加所有的域密钥，而不是特定域。     
每个域的选择加入控件通过要求用户在不熟悉的域的上下文中运行之前批准使用ActiveX控件来减少攻击面。 实际上，这需要攻击者将恶意Web内容插入受信任的域，以便偷偷地利用ActiveX控件。 图7显示了配置为在microsoft.com域内运行而没有提示的表格数据控件。
单个用户的选择性加入机制通过要求用户在执行不熟悉的域上下文中运行前确认ActiveX控件的方式来缩减攻击面。实际上，攻击者可以通过在授信的域名中插入恶意Web内容，偷偷地利用ActiveX控件。图7显示了表格数据控件允许在授信的mircosoft.com域运行前无需提示的配置信息。

图7	表格数据控件配置信息
Internet Explorer 权限 GUI界面
除了提供限制功能外，Mircosoft还给InternetExplorer提供了一个增强界面。用户可通过该界面轻松配置ActiveX控件权限，无需修改注册表。图8显示了访问Add-on界面的方法，图9显示了在未经许可前提下查找允许浏览器运行dll的方法。

图8	Add-on管理界面

图9 未经允许的情况下查看控件运行状况的方法
ActiveX安全总结
ActiveX有许多限制可以加载哪些控件，以及如何在给定的上下文中对它们执行操作的方法。一个可能的原因是：随着应用程序互操作性的增加，攻击者可利用的机会也大大增加了。在这个前提下，ActiveX控件的安全性以攻击----响应的方式在发展，这也导致了ActiveX支离破碎的安全架构。在后面的内容中，我们将展示一种绕过这些限制的攻击方法。该方法主要利用了Mircosoft总是临时向浏览器补充安全功能，而不是从一开始就建立了强大的安全架构的因素。
