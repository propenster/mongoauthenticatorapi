using System;
using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace MongoAuthenticatorAPI.Models
{
    [CollectionName("roles")]
    public class ApplicationRole : MongoIdentityRole<Guid>
    {
        
    }
}

