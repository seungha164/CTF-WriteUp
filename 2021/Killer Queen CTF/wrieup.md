# Killeeer Queen CTF

### 1. Road safety Association [crypto]

```
c: 34709089913401150635163820358938916881993556790698827096314474131695180194656373592831158701400832173951061153349955626770351918715134102729180082310540500929299260384727841272328651482716425284903562937949838801126975821205390573428889205747236795476232421245684253455346750459684786949905537837807616524618

p: 7049378199874518503065880299491083072359644394572493724131509322075604915964637314839516681795279921095822776593514545854149110798068329888153907702700969

q: 11332855855499101423426736341398808093169269495239972781080892932533129603046914334311158344125602053367004567763440106361963142912346338848213535638676857

e: 65537
```

간단한 RSA문제다. 

**solution.py**

```python
from gmpy2 import *

def hex_to_string(code):
    l=len(code)
    for i in range(int(l/2)):
        c=code[i*2:i*2+2]
        print(chr(int(c,16)),end='')
    print('')
    
c=34709089913401150635163820358938916881993556790698827096314474131695180194656373592831158701400832173951061153349955626770351918715134102729180082310540500929299260384727841272328651482716425284903562937949838801126975821205390573428889205747236795476232421245684253455346750459684786949905537837807616524618

p=7049378199874518503065880299491083072359644394572493724131509322075604915964637314839516681795279921095822776593514545854149110798068329888153907702700969

q=11332855855499101423426736341398808093169269495239972781080892932533129603046914334311158344125602053367004567763440106361963142912346338848213535638676857

e=65537

n = p * q    # n = p*q
phi = (p-1) * (q-1)    # phi구하기

# d = divm(1, e, phi)   곱셈의 역원 구해주기
d = invert(e, phi)

hex_to_string(hex(pow(c,d,n))[2:])
```

**Flag**

> kqctf{y0uv3_6r4du473d_fr0m_r54_3l3m3n74ry_5ch00l_ac8770bdcebc}
> 

---

### 2. **sneeki snek [rev]**

python 바이트 코드가 포함된 pyteCode다.

이전에 풀어본적이 있어서 쉽게 풀었다

```python
	4           0 LOAD_CONST               1 ('')
              2 STORE_FAST               0 (f)

	5           4 LOAD_CONST               2 ('rwhxi}eomr\\^`Y')
              6 STORE_FAST               1 (a)

  6           8 LOAD_CONST               3 ('f]XdThbQd^TYL&\x13g')
             10 STORE_FAST               2 (z)

  7          12 LOAD_FAST                1 (a)
             14 LOAD_FAST                2 (z)
             16 BINARY_ADD
             18 STORE_FAST               1 (a)
```

```python
f=''
a='rwhxi}eomr\\^`Y'
z='f]XdThbQd^TYL&\x13g'
a = a+z
```

```
  8          20 LOAD_GLOBAL              0 (enumerate)
             22 LOAD_FAST                1 (a)
             24 CALL_FUNCTION            1
             26 GET_ITER
        >>   28 FOR_ITER                48 (to 78)
             30 UNPACK_SEQUENCE          2
             32 STORE_FAST               3 (i)
             34 STORE_FAST               4 (b)

  9          36 LOAD_GLOBAL              1 (ord)
             38 LOAD_FAST                4 (b)
             40 CALL_FUNCTION            1
             42 STORE_FAST               5 (c)

 10          44 LOAD_FAST                5 (c)
             46 LOAD_CONST               4 (7)
             48 BINARY_SUBTRACT
             50 STORE_FAST               5 (c)

 11          52 LOAD_FAST                5 (c)
             54 LOAD_FAST                3 (i)
             56 BINARY_ADD
             58 STORE_FAST               5 (c)

 12          60 LOAD_GLOBAL              2 (chr)
             62 LOAD_FAST                5 (c)
             64 CALL_FUNCTION            1
             66 STORE_FAST               5 (c)

 13          68 LOAD_FAST                0 (f)
             70 LOAD_FAST                5 (c)
             72 INPLACE_ADD
             74 STORE_FAST               0 (f)
             76 JUMP_ABSOLUTE           28

```

```python
	for i,b in enumerate(a):	# i : 번호, b:값
			c=ord(b)
			c-=7
			c=i
			c=chr(c)
			f+=c	
```

```
 14     >>   78 LOAD_GLOBAL              3 (print)
             80 LOAD_FAST                0 (f)
             82 CALL_FUNCTION            1
             84 POP_TOP
             86 LOAD_CONST               0 (None)
             88 RETURN_VALUE
```

```python
print(f)
```

**solution.py**

```python
f=''
a='rwhxi}eomr\\^`Y'
z='f]XdThbQd^TYL&\x13g'
a+=z
for i,b in enumerate(a):
    c=chr(ord(b)-7+i)
    f+=c

print(f)
```

**flag**

> kqctf{dont_be_mean_to_snek_:(}
> 

[http://pymotw.com/2/dis/](http://pymotw.com/2/dis/)

[https://python.flowdas.com/library/dis.html](https://python.flowdas.com/library/dis.html)

---

### 2. **sneeki snek 2 oh no what did i do[rev]**

```python
 4           0 BUILD_LIST               0
            2 STORE_FAST               0 (a)

  5           4 LOAD_FAST                0 (a)
              6 LOAD_METHOD              0 (append)
              8 LOAD_CONST               1 (1739411)
             10 CALL_METHOD              1
             12 POP_TOP

  6          14 LOAD_FAST                0 (a)
             16 LOAD_METHOD              0 (append)
             18 LOAD_CONST               2 (1762811)
             20 CALL_METHOD              1
             22 POP_TOP
.
.
.

 34         294 LOAD_FAST                0 (a)
            296 LOAD_METHOD              0 (append)
            298 LOAD_CONST              15 (1539421)
            300 CALL_METHOD              1
            302 POP_TOP

 36         304 LOAD_CONST              16 ('')
            306 STORE_FAST               1 (b)

 37         308 LOAD_FAST                0 (a)
            310 GET_ITER
        >>  312 FOR_ITER                80 (to 394)
            314 STORE_FAST               2 (i)

 38         316 LOAD_GLOBAL              1 (str)
            318 LOAD_FAST                2 (i)
            320 CALL_FUNCTION            1
            322 LOAD_CONST               0 (None)
            324 LOAD_CONST               0 (None)
            326 LOAD_CONST              17 (-1)
            328 BUILD_SLICE              3
            330 BINARY_SUBSCR
            332 STORE_FAST               3 (c)

 39         334 LOAD_FAST                3 (c)
            336 LOAD_CONST               0 (None)
            338 LOAD_CONST              17 (-1)
            340 BUILD_SLICE              2
            342 BINARY_SUBSCR
            344 STORE_FAST               3 (c)

 40         346 LOAD_GLOBAL              2 (int)
            348 LOAD_FAST                3 (c)
            350 CALL_FUNCTION            1
            352 STORE_FAST               3 (c)

 41         354 LOAD_FAST                3 (c)
            356 LOAD_CONST              18 (5)
            358 BINARY_XOR
            360 STORE_FAST               3 (c)

 42         362 LOAD_FAST                3 (c)
            364 LOAD_CONST              19 (55555)
            366 BINARY_SUBTRACT
            368 STORE_FAST               3 (c)

 43         370 LOAD_FAST                3 (c)
            372 LOAD_CONST              20 (555)
            374 BINARY_FLOOR_DIVIDE
            376 STORE_FAST               3 (c)

 44         378 LOAD_FAST                1 (b)
            380 LOAD_GLOBAL              3 (chr)
            382 LOAD_FAST                3 (c)
            384 CALL_FUNCTION            1
            386 INPLACE_ADD
            388 STORE_FAST               1 (b)
            390 EXTENDED_ARG             1
            392 JUMP_ABSOLUTE          312

 45     >>  394 LOAD_GLOBAL              4 (print)
            396 LOAD_FAST                1 (b)
            398 CALL_FUNCTION            1
            400 POP_TOP
            402 LOAD_CONST               0 (None)
            404 RETURN_VALUE
```

어렵다고 느낀 부분

> 334       LOAD_FAST                  3 (c)
336       LOAD_CONST               0 (None)
338       LOAD_CONST              17 (-1)
340       BUILD_SLICE                 2
342       BINARY_SUBSCR
344       STORE_FAST                3 (c)
> 

BUILD_SLICE) 슬라이싱을 의미. → '2' ⇒ 인자 개수를 의미

334~340 ⇒  c[(none):-1]을 의미.

결과) c=c[:-1] 

그 외의 부분들은 쉽게 해석 가능.

```python
4	a=[]
13	a.append(1516111)

14	a.append(1739411)

15	a.append(1582801)
...
34	a.appned(1539421)

---------------------------------
36	b=''
---------------------------------
37	for i in a	

38	str(i)		
	c=str(i)[::-1]

39	c=c[:-1]

40	c=int(c)

41	c^=5

42	c=c-55555

43	c=c//555 	 

44	b+=chr(c)

print(b)
```

**solution.py**

```python
a=[]
a.append(1739411)   
a.append(1762811)
a.append(1794011)
a.append(1039911)
a.append(1061211)
a.append(1718321)
a.append(1773911)
a.append(1006611)
a.append(1516111)
a.append(1739411)    
a.append(1582801)
a.append(1506121)
a.append(1783901)
a.append(1783901)
a.append(1773911)
a.append(1582801)
a.append(1006611)
a.append(1561711)
a.append(1039911)
a.append(1582801)
a.append(1773911)
a.append(1561711)
a.append(1582801)
a.append(1773911)
a.append(1006611)
a.append(1516111)
a.append(1516111)
a.append(1739411)
a.append(1728311)
a.append(1539421)

b=''
for i in a:
    c=(str(i)[::-1])
		c=c[:-1]
		c=(int)c
		c=c^5
		c=c-55555
		c=c//555
    b+=chr(c)

print(b)
```

**flag**

> kqctf{snek_waas_not_so_sneeki}
> 

TIp

파이썬을 통해, 자기가 이해한게 맞는지 직접 dis해서 알 수 있다.

```python
def f(*args):
   print(a)
if __name__ == '__main__':
    import dis
    dis.dis(f)
```

> 2          LOAD_GLOBAL              0 (print)
4          CALL_FUNCTION            1
6          POP_TOP
8          LOAD_CONST               0 (None)
10        RETURN_VALUE
> 

---

### **jazz [rev]**

자바 코드와, "9xLmMiI2znmPam'D_A_1:RQ;Il\*7:%i".R<"문자열이 주어짐.

```java
import java.util.*;
import java.io.*;
public class challenge {
   public static void main(String[] args) throws FileNotFoundException {
      Scanner s = new Scanner(new BufferedReader(new FileReader("flag.txt")));
      String flag = s.nextLine();
      
      char[] r2 = flag.toCharArray();
      String build = "";
      for(int a = 0; a < r2.length; a++)
      {
         build += (char)(158 - r2[a]);
      }
      r2 = build.toCharArray();
      build = "";
      for(int a = 0; 2*a < r2.length - 1; a++)
      {
         build += (char)((2*r2[2*a]-r2[2*a+1]+153)%93+33);
         build += (char)((r2[2*a+1]-r2[2*a]+93)%93+33);
      }
      System.out.println(build);

      
      
   }
}
```

### sol

위 파일을 decrypt하는 코드 작성.

```java
String build = "";
      for(int a = 0; a < r2.length; a++)
      {
         build += (char)(158 - r2[a]);
      }
```

위 부분은 간단하게,

(158 - build[index])해주면 된다.

```java
build = "";
      for(int a = 0; 2*a < r2.length - 1; a++)
      {
         build += (char)((2*r2[2*a]-r2[2*a+1]+153)%93+33);
         build += (char)((r2[2*a+1]-r2[2*a]+93)%93+33);
      }
```

최종 build값을 알고있지만, %연산자 때문에 r2의 정확한 값을 알 수 없다.

⇒ 브루트포스로 위의 2가지 조건을 만족하는 값을 찾자.

**solution.py**

```java
package ctf;

public class chanllenge {
	
	 String cipher="9xLmMiI2znmPam'D_A_1:RQ;Il\\*7:%i\".R<";
	 
	public static void main(String[] args) {
	      chanllenge c = new chanllenge();
	      c.decrypt();
	   }
	
	void decrypt() {
		 String build = "";
		 for(int a=0;2*a<cipher.length();a++) {
			 // brute-force
			 for(int num1=0;num1<500;num1++) {
				 for(int num2=0;num2<500;num2++) {
					 if(challenge1(a,num1,num2))
							 challenge2(num1,num2); 
					 
				 }	 
			 }
		 }
	}
	boolean challenge1(int index,int num1, int num2) {
		if(cipher.charAt(index*2) ==(char)((2*num1-num2+153)%93+33)
				 && cipher.charAt(index*2+1) ==(char)((num2-num1+93)%93+33))
			return true;
		else
			return false;
	}

	void challenge2(int a,int b) {
		
		int num1=158-a;
		int num2=158-b;
		if( num1>=33 &&  num1<129 && num2>=33 && num2<129) {
			System.out.print((char)num1);
			System.out.print((char)num2);
		}
	}

}
```

**flag**

kqctf{D34D_0N_T1|\/|3_3vgy90N51Fob1s}
