
package main

import (
    "fmt"
    "unsafe"
    "reflect"
)

func container_of(p interface{}, st interface{}, member string) (unsafe.Pointer, bool){
	ss := reflect.TypeOf(st)
    var offset int = 0
	if ss.Kind() == reflect.Struct {
        mb, ok := ss.FieldByName(member)
        if !ok {
            fmt.Printf("FieldByName %s fail\n", member)
            return nil, false
        }      
		for i := 0 ; i < ss.NumField(); i++ {
            if ss.Field(i).Name == mb.Name {
                break
            }
            fmt.Printf("field name=%s\n", ss.Field(i).Name)
            switch t := ss.Field(i).Type.Kind(); t {
                case reflect.String:
                    offset += int(unsafe.Sizeof(string("a")))
                case reflect.Int,reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64:
                    offset += int(unsafe.Sizeof(int(0)))
                //case reflect.Int32, reflect.Uint32:
                //    offset += int(unsafe.Sizeof(int32(0)))
                default:
                    fmt.Printf("unknow type t=%v \n", t)
                    return nil, false
            }
        }
	}
    fmt.Printf("offset =%d, uintptr(offset)=%d\n", offset,  uintptr(offset))

	pt := reflect.TypeOf(p)
	if pt.Kind() == reflect.Ptr {
            fmt.Println(pt)                  
            switch p.(type) {
                case *int:
                    return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*int)))- uintptr(offset)), true
                case *int32:
                    return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*int32)))- uintptr(offset)), true
                case *uint32:
                    return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*uint32)))- uintptr(offset)), true
                case *int64:
                    return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*int64)))- uintptr(offset)), true
                case *uint64:
                    return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*uint64)))- uintptr(offset)), true               
                case *string:
                     return unsafe.Pointer(uintptr(unsafe.Pointer(p.(*string)))- uintptr(offset)), true
            }
			
	}
    return nil, false
}

type worker struct {
        name   string
        high    int32
        bieming   string
}

func main() {
    a := [4]int{0, 1, 2, 3}
    p1 := unsafe.Pointer(&a[1])
    p3 := unsafe.Pointer(uintptr(p1) + 2 * unsafe.Sizeof(a[0]))
    *(*int)(p3) = 6
    fmt.Printf("a[0] unsafe.Sizeof=%d, unsafe.Alignof =%d \n", unsafe.Sizeof(a[0]), unsafe.Alignof(a[1]))
    fmt.Println("a =", a) // a = [0 1 2 6]
    
    // ...

    type Person struct {
        name   string
        high    int32
        alias   string
        money   int64
        age    int
        gender bool
    }

    who := Person{name: "John", high: 170, alias: "datou", age: 30, gender: true}
    pp := unsafe.Pointer(&who)
    pname := (*string)(unsafe.Pointer(uintptr(pp) + unsafe.Offsetof(who.name)))
    page := (*int)(unsafe.Pointer(uintptr(pp) + unsafe.Offsetof(who.age)))
    pgender := (*bool)(unsafe.Pointer(uintptr(pp) + unsafe.Offsetof(who.gender)))
    *pname = "Alice123456789abcdeeeeeeeeeee"
    *page = 28
    *pgender = false
    fmt.Println(who) // {Alice 28 false}
    fmt.Printf("name offsetof = %d\n", unsafe.Offsetof(who.name))
    fmt.Printf("high offsetof = %d, unsafe.Alignof=%d\n", unsafe.Offsetof(who.high), unsafe.Alignof(who.high))
    fmt.Printf("alias offsetof = %d\n", unsafe.Offsetof(who.alias))
    fmt.Printf("money offsetof = %d\n", unsafe.Offsetof(who.money))
    fmt.Printf("age offsetof =%d, unsafe.Alignof=%d, len(name)=%d\n", unsafe.Offsetof(who.age), unsafe.Alignof(who.age), len(who.name))
    fmt.Printf("gender offsetof =%d\n", unsafe.Offsetof(who.gender))
    fmt.Printf("-----------------check unsafe.Sizeof ----------------\n")
    fmt.Printf("string.sizeof=%d \n", unsafe.Sizeof(string("a")))
    fmt.Printf("int.sizeof=%d \n", unsafe.Sizeof(int(1)))
    fmt.Printf("int32.sizeof=%d \n", unsafe.Sizeof(int32(1)))
    fmt.Printf("uint32.sizeof=%d \n", unsafe.Sizeof(uint32(1)))
    fmt.Printf("int64.sizeof=%d \n", unsafe.Sizeof(int64(1)))
    fmt.Printf("uint64.sizeof=%d \n", unsafe.Sizeof(uint64(1)))

    w := (*Person)(unsafe.Pointer(uintptr(unsafe.Pointer(page)) - unsafe.Offsetof(who.age)))
    fmt.Println(w)
    if ww, ok := container_of(page, Person{}, "age"); ok {
        fmt.Println((*Person)(ww))      
    }else{
        fmt.Println("container_of fail \n")
    }

    if ww, ok := container_of(&w.alias, Person{}, "alias"); ok {      
        fmt.Println((*Person)(ww))
    } else {
       fmt.Println("container_of fail \n")
    }

     if ww, ok := container_of(&w.high, Person{}, "high"); ok {      
        fmt.Println((*Person)(ww))
    } else {
       fmt.Println("container_of fail \n")
    } 

    wk := (*worker)(unsafe.Pointer(w))
    fmt.Println(wk)
}