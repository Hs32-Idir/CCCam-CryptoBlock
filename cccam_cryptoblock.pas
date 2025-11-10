(*
 *  Author original : Andreas Öman & Luis Alves, Ported to delphi7 by Hs32-Idir
 *
 *   Web : http://wWw.Hs32-Idir.Tk
 *   GitHub : https://github.com/Hs32-Idir
 *   Thanks : https://www.developpez.net/forums/
 *
 *  This is a part of CCCam server cryptography.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*)

unit cccam_cryptoblock;

interface

{$R-}
{$Q-}

uses Windows;

type
 _crypt_mode_t =
 (
  Encrypt = 1,
  Decrypt = 0
 );

Type
  TCryptBlock = Class(TObject)

  private
    keytable:array[0..255] of Byte;{ = (0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,
                                      0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,
                                      0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,
                                      0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,
                                      0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0
                                      1,2,3,4,5);  }



    counter,sum,state: Byte;
  protected
    procedure uint8_swap(var p1, p2 : byte);
  public
    procedure _crypt_init(var key : array of byte; len : integer);
    procedure _crypt_mode(data:Array of byte; len :Integer; mode : _crypt_mode_t );
    procedure _decrypt(var data   : array of byte; len : integer);
    procedure _encrypt(var data   : array of byte; len : integer);
    destructor Destroy; override;
    constructor Create();
    procedure Clear;
end;
   procedure _crypt_xor(var buf : array of byte; cccam_str:string); cdecl;
   
implementation

constructor TCryptBlock.Create;
begin
  Clear;
  inherited Create;
end;

destructor TCryptBlock.Destroy;
begin
  Clear;
  inherited Destroy;
end;

procedure TCryptBlock.Clear;
begin
  FillChar(keytable, SizeOf(keytable), #0);
  counter := 0;
  sum := 0;
  state := 0;
end;

procedure TCryptBlock.uint8_swap(var p1, p2 : byte);
var
  tmp : byte;
begin
  tmp := p1;
  p1  := p2;
  p2  := tmp;
end;

procedure TCryptBlock._crypt_init(var key : array of byte; len : integer);
var
  i : Cardinal;
  j : byte;
begin
  i := 0;
  j := 0;
  for i := 0 to 255 do
  begin
    keytable[i] := i;
  end;
  for i := 0 to 255 do
  begin
    j  := j + (key[i mod len] + keytable[i]);
    uint8_swap(keytable[i], keytable[j]);
  end; 
  state := key[0];
  counter := 0;
  sum := 0;
end;

procedure TCryptBlock._decrypt(var data : array of byte; len : integer);
var
  i : integer;
  z : byte;
begin
  for i := 0 to len-1 do
  begin
    Inc(counter);
    sum  := sum + (keytable[counter]);
    uint8_swap(keytable[counter], keytable[sum]);
    z := data[i];
    data[i] := z  xor  keytable[(keytable[counter] + keytable[sum]) and $ff]  xor  state;
    z := data[i];
    state  := state xor z;
  end;
end;

procedure TCryptBlock._crypt_mode(data:Array of byte; len :Integer; mode : _crypt_mode_t );
var
  i:Integer;
  z:Byte;
begin
  for i := 0 to len-1 do
  begin
		Inc(counter);
		sum := sum + keytable[counter];
    uint8_swap(keytable[counter], keytable[sum]);
    z := data[i];

		data[i] := z xor keytable[(keytable[counter] + keytable[sum]) and $ff];
		data[i] := Data[i] xor state;

    case _crypt_mode_t(mode) of
		 Decrypt :	z := data[i];
		end;

		state := state xor z;
  end;
end;

procedure TCryptBlock._encrypt(var data : array of byte; len : integer);
var
  i : integer;
  z : byte;
begin
  for i := 0 to len-1 do
  begin
    Inc(counter);
    sum  := sum + (keytable[counter]);
    uint8_swap(keytable[counter], keytable[sum]);
    z := data[i];
    data[i] := z  xor  keytable[(keytable[counter] + keytable[sum]) and $ff]  xor  state;
    state   := state xor z;
  end;
end;

procedure _crypt_xor(var buf : array of byte; cccam_str:string); cdecl;
var
  i : ShortInt;
begin
  for i := 0 to 7 do
  begin
    buf[i + 8] := Byte(i * buf[i]);
    if i <= 5 then buf[i-1] := buf[i-1] xor ord(cccam_str[i]);
  end;
end;

 {
 Web : http://wWw.Hs32-Idir.Tk
 https://www.developpez.net/forums/
 }
 
end.
