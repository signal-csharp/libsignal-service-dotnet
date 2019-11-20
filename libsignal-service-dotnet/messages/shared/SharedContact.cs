using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice.messages.shared
{
    public class SharedContact
    {
        public Name Name { get; }
        public Avatar? Avatar { get; }
        public List<Phone>? Phone { get; }
        public List<Email>? Email { get; }
        public List<PostalAddress>? Address { get; }
        public string Organization { get; }

        public SharedContact(Name name,
                     Avatar? avatar,
                     List<Phone>? phone,
                     List<Email>? email,
                     List<PostalAddress>? address,
                     string? organization)
        {
            Name         = name;
            Avatar       = avatar;
            Phone        = phone;
            Email        = email;
            Address      = address;
            Organization = organization;
        }
    }

    public class Avatar
    {
        public SignalServiceAttachment Attachment { get; }
        public bool IsProfile { get; }

        public Avatar(SignalServiceAttachment attachment, bool isProfile)
        {
            Attachment = attachment;
            IsProfile  = isProfile;
        }
    }

    public class Name
    {
        public string? Display { get; }
        public string? Given { get; }
        public string? Family { get; }
        public string? Prefix { get; }
        public string? Suffix { get; }
        public string? Middle { get; }

        public Name(string? display, string? given, string? family, string? prefix, string? suffix, string? middle)
        {
            Display = display;
            Given = given;
            Family = family;
            Prefix = prefix;
            Suffix = suffix;
            Middle = middle;
        }
    }

    public class Phone
    {
        public enum PhoneType
        {
            HOME, WORK, MOBILE, CUSTOM
        }
        public string Value { get; }
        public PhoneType Type { get; }
        public string? Label { get; }

        public Phone(string value, PhoneType type, string? label)
        {
            Value = value;
            Type = type;
            Label = Label;
        }
    }

    public class Email
    {
        public enum EmailType
        {
            HOME, WORK, MOBILE, CUSTOM
        }
        public string Value { get; }
        public EmailType Type { get; }
        public string? Label { get; }

        public Email(string value, EmailType type, string? label)
        {
            Value = value;
            Type  = type;
            Label = label;
        }
    }

    public class PostalAddress
    {

        public enum PostalAddressType
        {
            HOME, WORK, CUSTOM
        }

        public PostalAddressType Type;
        public string? Label;
        public string? Street;
        public string? Pobox;
        public string? Neighborhood;
        public string? City;
        public string? Region;
        public string? Postcode;
        public string? Country;

        public PostalAddress(PostalAddressType type, string? label, string? street,
                             string? pobox, string? neighborhood,
                             string? city, string? region,
                             string? postcode, string? country)
        {
            Type = type;
            Label = label;
            Street = street;
            Pobox = pobox;
            Neighborhood = neighborhood;
            City = city;
            Region = region;
            Postcode = postcode;
            Country = country;
        }
    }
}
