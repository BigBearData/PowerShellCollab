   M S B A M L   `   `   `  ����Q  MSSRS Essential Install, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null?$clr-namespace:SSRS_Essential_InstallSSRS_Essential_Install  5   	   '    !SSRS_Essential_Install.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   6local$clr-namespace:SSRS_Essential_Install     5   	     � Title$  SSRS Essental Installer��5   	   $	��450��6)   $	��800��66   .��5	      � .+�5
   
   �� $��SSRS Server Name:��6   $
��Left=�6,   $��26��6G   $��	24,33,0,0q�6S   $	��Top=�6f   $	��131��6~   �� 5   
   $��Named Instance:��6   $
��Left=�6*   $��26��6E   $��
24,126,0,0q�6Q   $	��Top=�6e   $	��131��6}   �� 5   
   $��MSSQL Server Name:��6   $
��Left=�6-   $��26��6H   $��	24,95,0,0q�6T   $	��Top=�6g   $	��131��6   �� 5   
   $��SSRS Service Account:��6   $
��Left=�60   $��26��6K   $��	24,64,0,0q�6W   $	��Top=�6j   $	��131��6�   �� 5   
   -   5         ��Name$ SSRS_ServerName��5      $
��Left=�6+   $��26��6F   $��
173,33,0,0q�6R    �� TextWrapping$
 Wrap=�6f   $	��Top=�6z   $	��169��6�   �� 5   
   -   5        $ NamedInstance��5      $
��Left=�6)   $��26��6D   $��173,126,0,0q�6P   $
 Wrap=�6e   $	��Top=�6y   $	��169��6�   6�   �� 5   
   -   5        $ MSSQL_ServerName��5      $
��Left=�6,   $��26��6G   $��
173,95,0,0q�6S   $
 Wrap=�6g   $	��Top=�6{   $	��169��6�   �� 5   
   -   5        $ SSRS_ServiceAccount��5      $
��Left=�6/   $��26��6J   $��
173,64,0,0q�6V   $
 Wrap=�6j   $	��Top=�6~   $	��169��6�   �� 5   
   -   5        $ Output_SSRS_PreCheck��5      $
��Left=�60   $	��180��6K   $��
24,200,0,0q�6X   $
 Wrap=�6l   $	��Top=�6�   $	��733��6�   6�   �� 5   
   -   5         ��Name$ Button_RunPreCheck��5      $��Run Pre-Check��6-   $
��Left=�6E   $��26��6`   $��
395,33,0,0q�6l   $	��Top=�6�   $	��125��6�   �� 5   
   -   5        $ Button_InstallODW��5      $��Install ODW��6,   $
��Left=�6B   $��26��6]   $��
395,95,0,0q�6i   $	��Top=�6}   $	��125��6�   �� 5   
   -   5        $ Button_UploadReports��5      $��Upload Reports��6/   $
��Left=�6H   $��26��6c   $��
395,64,0,0q�6o   $	��Top=�6�   $	��125��6�   �� 5   
   $��Pre-Check OK:��6   $
��Left=�6(   $��26��6C   $��
540,33,0,0q�6O   $	��Top=�6c   $��87��6{   �� 5   
   -	   5         ��Name$ PreCheckCheck��5      $��CheckBox��6*   $
��Left=�6=   $��26��6X   $��
643,33,0,0q�6d   $	��Top=�6x   $��18��6�   6�   �� 5   
   $#��Skip if Default Instance used��6   $
��Left=�68   $��27��6S   $��173,152,0,0q�6_   $	��Top=�6t   $	��169��6�   $��10(�6�   5      5      