using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using RepositoryLayer.Repositories.Interface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RepositoryLayer.Repositories.Implementation
{
    public class Repository<T> : IRepository<T> where T : BaseEntity
    {
        private readonly MiniNetworkDBContext context;
        private readonly DbSet<T> entities;

        public Repository(MiniNetworkDBContext context)
        {
            this.context = context;
            entities = context.Set<T>();
            
        }
        public IQueryable<T> GetAll()
        {
            return entities.AsQueryable();
        }
        public T Get(int id)
        {
            return entities.SingleOrDefault(p => p.Id == id);
        }
        public void Add(T entity)
        {
            entities.Add(entity);
        }
    }
}
