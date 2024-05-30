// MIT License
//
// Copyright (c) 2024 Andrey Zhdanov (rivitna)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.


package main


import (
  "os"
  "math"
  "fmt"
)


const (
  PasswordChars string = "0123456789thequickbrownfoxjumpsoverthlazydogTHEQUICKBROWNFOXJUMPSOVERTHELAZYDOG!@#$&*-+=_;"
  PasswordLen = 64
)


// Main
func main() {

  err := SavePasswords("passwords.txt")
  if err != nil {
    fmt.Println("Error: Failed to save passwords")
    os.Exit(1)
  }
}


// Save password list
func SavePasswords(fileName string) error {

  f, err := os.Create(fileName)
  if err != nil { return err }
  defer f.Close()

  for i := 0; i <= 0xFFFF; i++ {
    seed := uint32(i) << 8
    pwd := GenPassword(seed)
    _, err = f.Write([]byte(pwd + "\n"))
    if err != nil { return err }
  }

  return nil
}


// Generate password
func GenPassword(seed uint32) string {

  var pwd [PasswordLen]byte
  var rnd float32

  for i := 0; i < PasswordLen; i++ {
    rnd, seed = VBRnd(seed)
    pwd[i] = PasswordChars[int(rnd * float32(len(PasswordChars)))]
  }
  return string(pwd[:])
}


// Visual Basic Randomize
func VBRandomize(seed float64) uint32 {

  n := uint32(math.Float64bits(seed) >> 32)
  return ((n << 8) ^ (n >> 8)) & 0xFFFF00
}


// Visual Basic Rnd
func VBRnd(seed uint32) (float32, uint32) {

  seed = (0xFFC39EC3 - seed * 0x2BC03) & 0xFFFFFF
  return (float32(seed) * float32(5.9604645e-8)), seed
}
