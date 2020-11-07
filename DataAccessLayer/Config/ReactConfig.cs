using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Config
{
    public class ReactConfig
    {
        public ReactConfig(EntityTypeBuilder<React> entityBuilder)
        {
            entityBuilder.HasKey(r =>
                            new { r.PersonId, r.PostId });
            entityBuilder.HasOne<Post>(r => r.Post).WithMany(pr => pr.Reacts).OnDelete(DeleteBehavior.NoAction);
        }
    }
}
