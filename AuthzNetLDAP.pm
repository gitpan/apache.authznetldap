package Apache::AuthzNetLDAP;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

use Net::LDAP;
use mod_perl;
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED);
use URI;


@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
$VERSION = '0.01';
#bootstrap Apache::AuthzNetLDAP $VERSION;

# Preloaded methods go here.

#will determine if an entry in LDAP server is a member of a givengroup
#will handle groupofmembers, groupofuniquemembers, or Netscape's dynamic group
#eventually will handle LDAP url to add support for LDAP servers that don't support
#dynamic groups

#in future we should store user's DN in global cache to reduce searches on LDAP server
#also share LDAP connection


#proccesses a require directive
sub handler

{
 my $r = shift; 

   my $requires = $r->requires;

   return DECLINED unless $requires;


   my $username = $r->connection->user;


  #need to step through each requirement, handle valid-user, return OK once have match , otherwise return failure
   my $binddn = $r->dir_config('BindDN') || "";
   my $bindpwd = $r->dir_config('BindPWD') || "";
   my $basedn = $r->dir_config('BaseDN') || ""; 
   my $ldapserver = $r->dir_config('LDAPServer') || "localhost";
   my $ldapport = $r->dir_config('LDAPPort') || 389;
   my $uidattr = $r->dir_config('UIDAttr') || "uid";
    
   #first we connect to the LDAP server 
   my $ldap = new Net::LDAP($ldapserver, port => $ldapport);

   #initial bind as user in Apache config
   my $mesg = $ldap->bind($binddn, password=>$bindpwd);
  
   #each error message has an LDAP error code
   if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED; 
   }

   #first let's get the user's DN 
   my $attrs = ['dn'];
   $mesg = $ldap->search(
                  base => $basedn,
                  scope => 'sub',                  
                  filter => "($uidattr=$username)",
                  attrs => $attrs
                 );

  				 
    if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED;
   }
   my $entry = $mesg->shift_entry(); 
 
   #now let's find out if they are a member or not!
   #now process require
      
   for my $req(@{$requires})
   {
     # my $temps = $req->{requirement};
     # $r->log_reason("DEBUG requirement is $temps",$r->uri);

       my ($requirement,@rest) = split(/\s+/, $req->{requirement});
     if (lc $requirement eq 'user')
     {
        foreach (@rest) {return OK if $username eq $_;}
     }
     elsif (lc $requirement eq 'group')
    {
      my $temps = $req->{requirement};
      $r->log_reason("DEBUG requirement is $temps",$r->uri);
        my ($foo,$group) = split(/"/,$req->{requirement}); 
         my $isMember = Apache::AuthzNetLDAP::_getIsMember($ldap,$r,$group,$entry->dn());
         $r->log_reason("user $username: group($group) DEBUG - isMember: $isMember",$r->uri);
         return OK if $isMember;
     }
	  elsif (lc $requirement eq 'ldap-url')
	 {
	     my ($foo,$url) = split (/ldap-url/,$req->{requirement});
        my $isMember = Apache::AuthzNetLDAP::_checkURL($r,$ldap,$entry->dn(),$url);
		$r->log_reason("user $username: group($url) DEBUG - isMember: $isMember",$r->uri);
		return OK if $isMember;
      }	     
     elsif (lc $requirement eq 'valid-user') {
         return OK;
              }
   }       
  
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: group (test) LDAP membership check failed with ismember: DEBUG REMOVE COMMENT",$r->uri);
        return AUTH_REQUIRED;
   
 
  
}

sub _getIsMember
{
   my ($ldap,$r,$groupDN,$userDN) = @_;

   my $isMember = 0;
           $r->log_reason("DEBUG start _getIsMember $isMember",$r->uri);

       #if user is a member then this will compare to true and we're done
       my $mesg = $ldap->compare($groupDN,attr=>"uniquemember",value=>$userDN);
             my $code = $mesg->code();

       unless ($code == 6 || $code == 5)
       {
         $r->log_reason("_getIsMember failed because of LDAP failure $code for $groupDN",$r->uri); 
          return $isMember;
       }

        
      if ($mesg->code() == 6)
      {
        $isMember = 1;
        $r->log_reason("DEBUG isMember after compare is $isMember",$r->uri);
        return $isMember;
    
      }
      else #might be "groupofnames" object
      {
        $mesg = $ldap->compare($groupDN,attr=>"member",value=>$userDN);

        if ($mesg->code() == 6)
        {
           return 1;
          $isMember = 1;
        } 
       }    
      
        return $isMember if $isMember;
         

      #ok so you're not a member of this group, perhaps a member of the group
      #is also a group and you're a member of that group


      my @groupattrs = ["uniquemember","objectclass","memberurl", "member"];

      $mesg = $ldap->search(
               base => $groupDN,
	       filter => "(|(objectclass=groupOfUniqueNames)(objectclass=groupOfNames)(objectclass=groupOfUrls))",
	       attrs => @groupattrs
	       );

 if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $userDN: group ($groupDN) LDAP search Failed: $error",$r->uri);
        return AUTH_REQUIRED;
   }
      my $entry = $mesg->pop_entry();


      #check to see if our entry matches the search filter

      my $urlvalues = $entry->get("memberurl");

      foreach my $urlval (@{$urlvalues})
      {

         my $uri = new URI ($urlval);


         my $filter = $uri->filter();

	 my @attrs = $uri->attributes();

         $mesg = $ldap->search(
               base => $userDN,
	       scope => "base",
	       filter => $filter,
	       attrs => \@attrs
	       );

          if (my $error = $mesg->code())
        {
          $r->note_basic_auth_failure;
          $r->log_reason("user $userDN: group ($groupDN) LDAP search Failed: $error",$r->uri);
          return AUTH_REQUIRED;
        }

        #if we find an entry it returns true
	#else keep searching
	
	   my $entry = $mesg->pop_entry();

	  $isMember  = 1;
	  return $isMember;


      } #end foreach

      my $membervalues = $entry->get("uniquemember");
    
     foreach my $val (@{$membervalues})
     {

       #my $isMember = Apache::AuthzNetLDAP::getIsMember($val,$userDN);
         $isMember = Apache::AuthzNetLDAP::_getIsMember($ldap,$r,$val,$userDN);
       #stop as soon as we have a winner
   #    last if $isMember;
       return $isMember if $isMember;
     }
     
     unless ($isMember)
     {
       my $membervalues = $entry->get("member");
    
       foreach my $val (@{$membervalues})
       {
         my $isMember = Apache::AuthzNetLDAP::_getIsMember($ldap,$r,$val,$userDN);
       #  my $isMember = &getIsMember($val,$userDN);

         #stop as soon as we have a winner
        # last if $isMember;
                  return $isMember if $isMember;
       }
      }
      if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $userDN: group ($groupDN) LDAP search Failed: $error",$r->uri);
        return AUTH_REQUIRED;
   }

     #if make it this far then you must be a member
  
     return $isMember;

   #if this far we are not a member 
   return 0;
  
}

#says whether a user's entry matches search query in LDAP URL
#need to replace code in isMember with a call to this routine
sub _checkURL
{
   my ($r,$ldap,$userDN,$urlval) = @_;
   my $uri = new URI ($urlval);


     my $filter = $uri->filter();

	 my @attrs = $uri->attributes();

        my $mesg = $ldap->search(
               base => $userDN,
	       scope => "base",
	       filter => $filter,
	       attrs => \@attrs
	       );

          if (my $error = $mesg->code())
        {
          $r->note_basic_auth_failure;
          $r->log_reason("user $userDN: group ($urlval) LDAP search Failed: $error",$r->uri);
          return AUTH_REQUIRED;
        }

        #if we find an entry it returns true
       # my $entry = $mesg->pop_entry();

	   if ($mesg->pop_entry())
	   {
	        return 1;
	   }
	   else
	   {
	      return 0;
		}
}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Apache::AuthzNetLDAP - Apache-Perl module that enables you to authorize a user for Website
based on LDAP attributes.

=head1 SYNOPSIS

  use Apache::AuthzNetLDAP;
  PerlSetVar BindDN "cn=Directory Manager"
  PerlSetVar BindPWD "password"
  PerlSetVar BaseDN "ou=people,o=unt.edu"
  PerlSetVar LDAPServer ldap.unt.edu
  PerlSetVar LDAPPort 389
  PerlSetVar UIDAttr uid
 #PerlSetVar UIDAttr mail 
   
  PerlAuthenHandler Apache::AuthNetLDAP
  PerlAuthzHandler Apache::AuthzNetLDAP
  
  #require valid-user     
  #require user mewilcox
  #require user mewilcox@venus.acs.unt.edu
  #require group "cn=Peoplebrowsers1,ou=UNTGroups,ou=People, o=unt.edu"
  #require ldap-url ldap://pandora.acs.unt.edu/o=unt.edu??sub?sn=wilcox
  #require ldap-url ldap://pandora.acs.unt.edu/o=unt.edu??sub?sn=smith
  #require ldap-url ldap://castor.acs.unt.edu/ou=people,o=unt.edu??sub?untcourse=
untcoursenumber=1999CCOMM2040001,ou=courses,ou=acad,o=unt.edu
 
=head1 DESCRIPTION

After you have authenticated a user (perhaps with Apache::AuthNetLDAP ;) 
you can use this module to determine whether they are authorized to access
the Web resource under this modules control.

You can control authorization via one of four methods. The first two are
pretty standard, the second two are unique to LDAP.

=item user I<username>
Will authorize access if the authenticated user's I<username>.

=item valid-user
Will authorize any authenticated user.

=item group I<groupdn>
Will authorize any authenticated user who is a member of the LDAP group
specified by I<groupdn>. This module supports groupOfMember, groupOfUniquemember
and Netscape's dynamic group object classes.

=item ldap-url I<ldap-url>
This will authorize any authenticated user who matches the query specified
in the given LDAP URL. This is enables users to get the flexibility of Netscape's
dynamic groups, even if their LDAP server does not support such a capability.  

=head1 AUTHOR

Mark Wilcox mewilcox@unt.edu

=head1 SEE ALSO

perl(1).

=head1 WARRANTY
Hey, I didn't destroy mankind when testing the module. You're mileage may vary. 

This module is distributed with the same license as Perl's.
=cut
