using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Config
{
    public class PostConfig
    {
        public PostConfig(EntityTypeBuilder<Post> entityBuilder)
        {
            entityBuilder.HasKey(p => p.Id);
            entityBuilder.HasOne<Person>(p => p.Person).WithMany(pr => pr.Posts).OnDelete(DeleteBehavior.Cascade);
            entityBuilder.Property(p => p.Text).IsRequired();
            entityBuilder.Property(p => p.ImagePath).IsRequired();
        }
    }
}
