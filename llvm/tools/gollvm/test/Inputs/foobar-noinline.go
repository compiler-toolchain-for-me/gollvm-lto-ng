package foobar

//go:noinline
func Foo(i int) {
  println(i)
}

//go:noinline 
func Bar(i int) {
  println(i)
}

