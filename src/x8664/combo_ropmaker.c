/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "ropgadget.h"

/* gadget necessary for combo */
/* don't touch this att syntax for parsing */
static char *tab_combo_ropsh[] =
{
  "syscall", NULL,
  "inc %rax", "inc %eax", NULL,
  "xor %rax,%rax", "mov $0x0,%rax", NULL,
  "mov %r?x,(%r?x)", NULL,
  "pop %rax", NULL,
  "pop %rbx", NULL,
  "pop %rcx", NULL,
  "pop %rdx", NULL,
  NULL
};

/* gadget necessary for combo importsc */
static char *tab_combo_importsc[] =
{
  "mov %r?x,(%r?x)",
  "",                 /*set in combo_ropmaker_importsc() */
  "",                 /*            //            */
  "",                 /*            //            */
  NULL
};

static void x64_combo_ropmaker(int target)
{
  int flag = 0;
  int useless = -1;
  t_list_inst *list_ins = NULL;

  char **ropsh = target == -1?tab_combo_importsc:tab_combo_ropsh;

  if (target == -1)
    {
      char reg1, reg2, reg3;
      char gad1[] = "pop %rXx";
      char gad2[] = "mov (%rXx),%rXx";
      char gad3[] = "mov %rXx,%rXx";
      Elf64_Addr addr = search_instruction(tab_x8664, ropsh[0]);
      if (addr)
        {
          reg1 = getreg(get_gadget_since_addr_att(tab_x8664, addr), 1);
          reg2 = getreg(get_gadget_since_addr_att(tab_x8664, addr), 2);
          ropsh[2] = gad1;
          ropsh[4] = gad2;
          ropsh[6] = gad3;
          ropsh[2][6]  = reg2;
          ropsh[4][7]  = reg2;
          ropsh[4][13] = '?';
          addr = search_instruction(tab_x8664, ropsh[4]);
          reg3 = getreg(get_gadget_since_addr_att(tab_x8664, addr), 3);
          ropsh[6][6]  = reg3;
          ropsh[6][11] = reg1;

          if (reg3 == reg1) {/* gadget useless */
            useless = 3;    /* gadget 3 */
            ropsh[6] = NULL;
          }
        }
    }

  flag = combo_ropmaker(ropsh, tab_x8664, &list_ins);

  if (target == -1)
    {
      if (importsc_mode.size > (importsc_mode.gotsize + importsc_mode.gotpltsize))
        {
          fprintf(stderr, "\n\t%s/!\\ Possible to make a ROP payload but .got size & .got.plt size isn't sufficient.%s\n", RED, ENDC);
          fprintf(stderr, "  \t%s    got + got.plt = %s" SIZE_FORMAT " bytes%s and your shellcode size is %s" SIZE_FORMAT " bytes%s\n", RED, YELLOW, (importsc_mode.gotsize + importsc_mode.gotpltsize), RED, YELLOW, (Size)importsc_mode.size, ENDC);
          return ;
        }
      /* build a python code */
/*      if (!flag)
        x8664_makecode_importsc(list_ins, useless, ropsh[1]); */
    }
  else
    {
    /* build a python code */
/*    if (!flag)
      x8664_makecode(list_ins); */
    }
}

void x8664_ropmaker(void)
{
  if (importsc_mode.flag)
    x64_combo_ropmaker(-1);
  else
    {
      x64_combo_ropmaker(1);
      x64_combo_ropmaker(2);
    }
}